
/*
# MIT No Attribution

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
const aws = require("aws-sdk");

exports.handler = (event, context, callback) => {
    // TODO implement
    console.log(JSON.stringify(event))
    console.log(event.Records[0].Sns.Message)
    var stepfunctions = new aws.StepFunctions();
    var stepMessage = JSON.parse(event.Records[0].Sns.Message);
    console.log(stepMessage.detail);
    console.log(stepMessage.detail["instance-id"]);
    var instanceID = stepMessage.detail["instance-id"];
    var stepevent = '{"instanceID" :"' + instanceID + '"}'
    var params = {
          stateMachineArn: process.env.STEP_FUNCTION_ARN, /* required */
          input: stepevent,
          name: 'IncidentResponse-1' + new Date().getTime()
        };
        stepfunctions.startExecution(params, function(err, data) {
          if (err) console.log(err, err.stack); // an error occurred
          else     console.log(data);           // successful response
        });
    callback(null, 'Step Functions Successfully invoked');
};
