import * as cdk from 'aws-cdk-lib';
import * as cloudformation from 'aws-cdk-lib/aws-cloudformation';
import { Construct } from 'constructs';

export interface StackSetManagementStackProps extends cdk.StackProps {
  templateBody: string;
  stackSetName: string;
  organizationalUnitIds: string[];
  regions: string[];
  /**
   * StackSet 操作の実行者種別。
   * マネジメントアカウントからは 'SELF' (デフォルト)、
   * 委任管理者(delegated administrator)からは 'DELEGATED_ADMIN' を指定する。
   */
  callAs?: 'SELF' | 'DELEGATED_ADMIN';
}

/**
 * AccountTemplateStack の synth 結果を StackSet に埋め込み、
 * Organizations 配下の全アカウントへ IAM Role を配布する。
 *
 * Git sync で管理する対象はこの Stack のみ。
 * permissionModel: SERVICE_MANAGED — Organizations 自動連携。
 */
export class StackSetManagementStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: StackSetManagementStackProps) {
    super(scope, id, props);

    const { templateBody, stackSetName, organizationalUnitIds, regions, callAs } = props;

    new cloudformation.CfnStackSet(this, 'TargetRoleStackSet', {
      permissionModel: 'SERVICE_MANAGED',
      callAs: callAs ?? 'SELF',
      stackSetName,
      capabilities: ['CAPABILITY_NAMED_IAM'],
      autoDeployment: {
        enabled: true,
        retainStacksOnAccountRemoval: false,
      },
      stackInstancesGroup: [
        {
          deploymentTargets: {
            organizationalUnitIds,
          },
          regions,
        },
      ],
      templateBody,
    });
  }
}
