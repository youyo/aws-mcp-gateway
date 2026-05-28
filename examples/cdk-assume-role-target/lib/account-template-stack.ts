import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface AccountTemplateStackProps extends cdk.StackProps {
  sourceAccountId: string;
  externalId: string;
  roleName: string;
  /**
   * 指定した場合は assumedBy を AccountPrincipal ではなく ArnPrincipal に絞り込む。
   * aws-mcp-gateway の実行ロール ARN を指定すると、より厳格な信頼ポリシーになる。
   */
  gatewayRoleArn?: string;
}

/**
 * 各 AWS アカウントへ配布される IAM Role 定義。
 * StackSets で全ターゲットアカウントに同一の Role を作成する。
 */
export class AccountTemplateStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AccountTemplateStackProps) {
    super(scope, id, props);

    const { sourceAccountId, externalId, roleName, gatewayRoleArn } = props;

    // gatewayRoleArn 指定時は ArnPrincipal で principal を絞り込む。
    // 未指定時は source account の root を信頼し、ExternalId 条件で保護する。
    const assumedBy = (
      gatewayRoleArn
        ? new iam.ArnPrincipal(gatewayRoleArn)
        : new iam.AccountPrincipal(sourceAccountId)
    ).withConditions({
      StringEquals: {
        'sts:ExternalId': externalId,
      },
    });

    new iam.Role(this, 'TargetRole', {
      roleName,
      assumedBy,
      // aws-mcp-gateway が使用する権限 — 必要に応じて変更してください
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess'),
      ],
    });
  }
}
