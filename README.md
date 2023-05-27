<h1>Qualys Continuous Monitoring - Slack Integration Module</h1>
<p>This module does the following:</p>
<ul>
    <li>Lists Qualys CM alerts for specified Qualys Account hourly (time you specified)</li>
    <li>Parses JSON alerts for getting attributes. There are 2 types of alerts for attributes:
        <ul>
            <li>Vulnerability alerts</li>
            <li>Certificate/Port alerts</li>
        </ul>
    </li>
    <li>Creates message payload for Slack creating message API request</li>
    <li>Sends message to Slack Webhook (to main and backup webhooks)</li>
</ul>

<h2>Getting Started</h2>
<p>These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.</p>

<h3>Prerequisites</h3>
<p>You'll need the following:</p>
<ul>
    <li>Python 3.7 or later</li>
    <li>AWS account with access to AWS Secrets Manager</li>
    <li>An environment with the following variables:
        <ul>
            <li>SLACK_MAIN_CHANNEL: The URL of your main Slack channel</li>
            <li>SLACK_BACKUP_CHANNEL: The URL of your backup Slack channel</li>
            <li>QUALYS_API_URL: The URL of the Qualys API</li>
            <li>REGION_NAME: The region for AWS Secrets Manager</li>
            <li>SECRET_NAME: The name of the secret in AWS Secrets Manager</li>
        </ul>
    </li>
</ul>

<h3>Installing</h3>
<p>To install the necessary libraries, run the following command:</p>
<pre><code>pip install requests xmltodict boto3</code></pre>

<h2>Usage</h2>
<p>This script is meant to be run as an AWS Lambda function. The entry point is the <code>lambda_handler</code> function. Here's a basic example of usage:</p>
<pre><code>event = {}</code></pre>

<h2>Built With</h2>
<ul>
    <li><a href="https://www.python.org/">Python</a></li>
    <li><a href="https://requests.readthedocs.io/">Requests</a></li>
    <li><a href="https://github.com/martinblech/xmltodict">xmltodict</a></li>
    <li><a href="https://github.com/boto/boto3">boto3</a></li>
</ul>
