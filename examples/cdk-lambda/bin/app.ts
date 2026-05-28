import * as cdk from 'aws-cdk-lib';
import { AwsMcpGatewayStack } from '../lib/aws-mcp-gateway-stack';

const app = new cdk.App();

const instanceName: string = app.node.tryGetContext('instanceName') ?? 'amg';
const awsMcpRegion: string = app.node.tryGetContext('awsMcpRegion') ?? 'us-east-1';
const targetAwsRegion: string = app.node.tryGetContext('targetAwsRegion') ?? 'ap-northeast-1';
const iamMode: string = app.node.tryGetContext('iamMode') ?? 'direct';
const assumeRoleArn: string = app.node.tryGetContext('assumeRoleArn') ?? '';
const federatedRoleArn: string = app.node.tryGetContext('federatedRoleArn') ?? '';

new AwsMcpGatewayStack(app, `${instanceName}-stack`, {
  instanceName,
  awsMcpRegion,
  targetAwsRegion,
  iamMode,
  assumeRoleArn: assumeRoleArn || undefined,
  federatedRoleArn: federatedRoleArn || undefined,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? targetAwsRegion,
  },
});
