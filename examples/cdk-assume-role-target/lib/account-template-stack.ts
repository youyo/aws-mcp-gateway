import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface AccountTemplateStackProps extends cdk.StackProps {
  sourceAccountId: string;
  externalId: string;
  roleName: string;
}

/**
 * 各 AWS アカウントへ配布される IAM Role 定義。
 * StackSets で全ターゲットアカウントに同一の Role を作成する。
 */
export class AccountTemplateStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AccountTemplateStackProps) {
    super(scope, id, props);

    const { sourceAccountId, externalId, roleName } = props;

    new iam.Role(this, 'TargetRole', {
      roleName,
      assumedBy: new iam.AccountPrincipal(sourceAccountId).withConditions({
        StringEquals: {
          'sts:ExternalId': externalId,
        },
      }),
      // aws-mcp-gateway が使用する権限 — 必要に応じて変更してください
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess'),
      ],
    });
  }
}
