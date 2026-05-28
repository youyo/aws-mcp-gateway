import * as cdk from 'aws-cdk-lib';
import * as fs from 'fs';
import * as path from 'path';
import { AccountTemplateStack } from '../lib/account-template-stack';
import { StackSetManagementStack } from '../lib/stackset-management-stack';

const app = new cdk.App();

const sourceAccountId: string = app.node.tryGetContext('sourceAccountId') ?? '111111111111';
const externalId: string = app.node.tryGetContext('externalId') ?? 'my-external-id';
const roleName: string = app.node.tryGetContext('roleName') ?? 'aws-mcp-gateway-target';
const organizationalUnitIds: string[] = app.node.tryGetContext('organizationalUnitIds') ?? ['ou-xxxx-yyyy'];
const regions: string[] = app.node.tryGetContext('regions') ?? ['ap-northeast-1'];
const stackSetName: string = app.node.tryGetContext('stackSetName') ?? roleName;

// Step 1: IAM Role テンプレートを生成するスタック (AWS にはデプロイしない)
// `cdk synth AccountTemplateStack` で cdk.out/ にテンプレート JSON が生成される
new AccountTemplateStack(app, 'AccountTemplateStack', {
  sourceAccountId,
  externalId,
  roleName,
});

// Step 2: 生成済みテンプレートを読み込んで StackSet に埋め込む
// AccountTemplateStack を先に synth した後に StackSetManagementStack を synth/deploy する
const templatePath = path.join(__dirname, '../cdk.out/AccountTemplateStack.template.json');
if (fs.existsSync(templatePath)) {
  const templateBody = fs.readFileSync(templatePath, 'utf-8');
  new StackSetManagementStack(app, 'StackSetManagementStack', {
    templateBody,
    stackSetName,
    organizationalUnitIds,
    regions,
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_DEFAULT_REGION ?? 'ap-northeast-1',
    },
  });
}
