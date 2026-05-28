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
      lambdaRole.addToPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['sts:AssumeRoleWithWebIdentity'],
        resources: ['*'],
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
    const externalUrl = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/EXTERNAL_URL`);
    const oidcIssuer = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/OIDC_ISSUER`);
    const oidcClientId = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/OIDC_CLIENT_ID`);
    const dynamodbTable = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/DYNAMODB_TABLE`);
    const dynamodbRegion = ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/DYNAMODB_REGION`);

    // SecureString は CloudFormation dynamic reference で参照
    const oidcClientSecret = `{{resolve:ssm-secure:/${instanceName}/OIDC_CLIENT_SECRET}}`;
    const cookieSecret = `{{resolve:ssm-secure:/${instanceName}/COOKIE_SECRET}}`;
    const federatedRoleArnSsm = federatedRoleArn
      ? federatedRoleArn
      : ssm.StringParameter.valueForStringParameter(this, `/${instanceName}/FEDERATED_ROLE_ARN`);

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
        AWS_MCP_REGION: awsMcpRegion,
        TARGET_AWS_REGION: targetAwsRegion,
        AWS_LWA_INVOKE_MODE: 'response_stream',
        ASSUME_ROLE_ARN: assumeRoleArn ?? '',
        IAM_MODE: iamMode,
        FEDERATED_ROLE_ARN: federatedRoleArnSsm,
        STORE_BACKEND: 'dynamodb',
        DYNAMODB_TABLE: dynamodbTable,
        DYNAMODB_REGION: dynamodbRegion,
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
