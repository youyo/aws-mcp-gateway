import * as cdk from 'aws-cdk-lib';
import * as fs from 'fs';
import * as path from 'path';
import { AccountTemplateStack } from '../lib/account-template-stack';
import { StackSetManagementStack } from '../lib/stackset-management-stack';

const app = new cdk.App();

// 必須 context — 未指定なら明示的にエラーにする (危険なプレースホルダのフォールバックは禁止)
const sourceAccountId: string | undefined = app.node.tryGetContext('sourceAccountId');
if (!sourceAccountId) {
  throw new Error('sourceAccountId context parameter is required');
}
const externalId: string | undefined = app.node.tryGetContext('externalId');
if (!externalId) {
  throw new Error('externalId context parameter is required');
}
// `-c` で渡された配列は文字列 (例: '["ou-xxxx-yyyy"]') として届くため JSON.parse する。
// cdk.json に配列で書いた場合は既に配列なのでそのまま使う。
const organizationalUnitIdsRaw = app.node.tryGetContext('organizationalUnitIds');
if (!organizationalUnitIdsRaw) {
  throw new Error('organizationalUnitIds context parameter is required');
}
const organizationalUnitIds: string[] = Array.isArray(organizationalUnitIdsRaw)
  ? organizationalUnitIdsRaw
  : JSON.parse(organizationalUnitIdsRaw);

// 安全に省略可能な context — デフォルト値を持つ
const roleName: string = app.node.tryGetContext('roleName') ?? 'aws-mcp-gateway-target';
const regionsRaw = app.node.tryGetContext('regions');
const regions: string[] = regionsRaw
  ? (Array.isArray(regionsRaw) ? regionsRaw : JSON.parse(regionsRaw))
  : ['ap-northeast-1'];
const stackSetName: string = app.node.tryGetContext('stackSetName') ?? roleName;

// 任意 context — 指定時は ArnPrincipal で principal を絞り込む
const gatewayRoleArn: string | undefined = app.node.tryGetContext('gatewayRoleArn');
const callAs: 'SELF' | 'DELEGATED_ADMIN' | undefined = app.node.tryGetContext('callAs');

// Step 1: IAM Role テンプレートを生成するスタック (AWS にはデプロイしない)
// `cdk synth AccountTemplateStack` で cdk.out/ にテンプレート JSON が生成される
new AccountTemplateStack(app, 'AccountTemplateStack', {
  sourceAccountId,
  externalId,
  roleName,
  gatewayRoleArn,
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
    callAs,
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.CDK_DEFAULT_REGION ?? 'ap-northeast-1',
    },
  });
} else {
  // テンプレート未生成のため StackSetManagementStack をスキップする。
  // 初回の `cdk synth AccountTemplateStack` 自体がこの状態で実行されるため throw はしない。
  console.warn(
    'StackSetManagementStack をスキップしました。先に "npx cdk synth AccountTemplateStack" を実行してテンプレートを生成してください。'
  );
}
