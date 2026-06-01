import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import * as path from 'path';

export interface AwsMcpGatewayStackProps extends cdk.StackProps {
  instanceName: string;
  awsMcpRegion: string;
  targetAwsRegion: string;
  iamMode: string;
  assumeRoleArn?: string;
  federatedRoleArn?: string;
}

export class AwsMcpGatewayStack extends cdk.Stack {
  public readonly functionUrl: lambda.FunctionUrl;

  constructor(scope: Construct, id: string, props: AwsMcpGatewayStackProps) {
    super(scope, id, props);

    const {
      instanceName,
      awsMcpRegion,
      targetAwsRegion,
      iamMode,
      assumeRoleArn,
      federatedRoleArn,
    } = props;

    // iamMode のバリデーション — main.go は "shared"/"federated" のみ有効
    const VALID_IAM_MODES = ['shared', 'federated'];
    if (!VALID_IAM_MODES.includes(iamMode)) {
      throw new Error(`Invalid iamMode: "${iamMode}". Must be one of: ${VALID_IAM_MODES.join(', ')}`);
    }

    // DynamoDB: セッションストア
    const sessionTable = new dynamodb.Table(this, 'SessionTable', {
      tableName: instanceName,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Lambda 実行ロール
    const lambdaRole = new iam.Role(this, 'LambdaRole', {
      roleName: `${instanceName}-lambda-role`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
        // AWS MCP アクセス権限 — 必要に応じて変更してください
        iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess'),
      ],
    });

    sessionTable.grantReadWriteData(lambdaRole);

    if (assumeRoleArn) {
      lambdaRole.addToPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['sts:AssumeRole'],
        resources: [assumeRoleArn],
      }));
    }

    if (iamMode === 'federated') {
      // federated モードでは引受先 Role ARN が必須 (main.go の前提と同じ)
      if (!federatedRoleArn) {
        throw new Error('federatedRoleArn is required when iamMode is "federated"');
      }
      lambdaRole.addToPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['sts:AssumeRoleWithWebIdentity'],
        resources: [federatedRoleArn],
      }));
    }

    // Lambda Web Adapter レイヤー (arm64)
    // 最新バージョン: https://github.com/awslabs/aws-lambda-web-adapter/releases
    const lwaLayer = lambda.LayerVersion.fromLayerVersionArn(
      this,
      'LwaLayer',
      `arn:aws:lambda:${this.region}:753240598075:layer:LambdaAdapterLayerArm64:27`,
    );

    // SSM パラメータ参照
    // デプロイ前に以下のパラメータを SSM Parameter Store に作成してください (README 参照)
    // シークレットを含め全て String 型パラメータをデプロイ時に解決して env へ注入
    // (CloudFormation の ssm-secure 動的参照は Lambda 環境変数では非対応のため String に統一)
    const externalUrl = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/EXTERNAL_URL`);
    const oidcIssuer = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/OIDC_ISSUER`);
    const oidcClientId = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/OIDC_CLIENT_ID`);
    const oidcClientSecret = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/OIDC_CLIENT_SECRET`);
    const cookieSecret = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/COOKIE_SECRET`);
    // SIGNING_KEY_HEX: OAuth 2.1 JWT 署名鍵（PKCS8 DER の hex エンコード）
    // Lambda 並行実行（複数インスタンス）でインスタンス間のトークン検証が成功するために必須。
    // COOKIE_SECRET と同様に全インスタンスで同一の値を共有する必要がある。
    // 生成: openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER -out signing.key && xxd -p -c 0 signing.key
    const signingKeyHex = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/SIGNING_KEY_HEX`);
    const dynamodbTable = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/DYNAMODB_TABLE`);
    const dynamodbRegion = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/DYNAMODB_REGION`);

    // Lambda 関数
    // asset/ ディレクトリに bootstrap バイナリを配置してください (README 参照)
    const fn = new lambda.Function(this, 'Function', {
      functionName: instanceName,
      description: 'OIDC-authenticated reverse proxy for AWS MCP Server',
      runtime: lambda.Runtime.PROVIDED_AL2023,
      handler: 'bootstrap',
      architecture: lambda.Architecture.ARM_64,
      memorySize: 256,
      timeout: cdk.Duration.seconds(900),
      role: lambdaRole,
      code: lambda.Code.fromAsset(path.join(__dirname, '../asset')),
      layers: [lwaLayer],
      environment: {
        EXTERNAL_URL: externalUrl,
        OIDC_ISSUER: oidcIssuer,
        OIDC_CLIENT_ID: oidcClientId,
        OIDC_CLIENT_SECRET: oidcClientSecret,
        COOKIE_SECRET: cookieSecret,
        SIGNING_KEY_HEX: signingKeyHex,
        AWS_MCP_REGION: awsMcpRegion,
        TARGET_AWS_REGION: targetAwsRegion,
        AWS_LWA_INVOKE_MODE: 'response_stream',
        ASSUME_ROLE_ARN: assumeRoleArn ?? '',
        IAM_MODE: iamMode,
        STORE_BACKEND: 'dynamodb',
        DYNAMODB_TABLE: dynamodbTable,
        DYNAMODB_REGION: dynamodbRegion,
        // FEDERATED_ROLE_ARN は federated モード時のみ設定 (main.go の必須要件と一致)
        ...(iamMode === 'federated' ? { FEDERATED_ROLE_ARN: federatedRoleArn! } : {}),
      },
    });

    // Function URL
    this.functionUrl = fn.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.NONE,
      invokeMode: lambda.InvokeMode.RESPONSE_STREAM,
    });

    new cdk.CfnOutput(this, 'FunctionUrl', {
      value: this.functionUrl.url,
      description: 'Lambda Function URL — 初回 deploy 後にこの値を SSM /${instanceName}/EXTERNAL_URL に設定して再 deploy してください',
    });

    new cdk.CfnOutput(this, 'LambdaRoleArn', {
      value: lambdaRole.roleArn,
      description: 'Lambda 実行ロール ARN',
    });

    new cdk.CfnOutput(this, 'DynamoDbTableName', {
      value: sessionTable.tableName,
      description: 'DynamoDB セッションテーブル名',
    });
  }
}
