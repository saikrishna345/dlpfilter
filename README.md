# dlpfilter

### Prerequisites:
You must have the following setup on your environment:
- NodeJs development
- Google's fluentd logger agent
> Note: If your environment doesn't meet the above prerequisites, please follow the instructions in the next step.

### Environment setup:
> Note: 
    1) You need to setup the following environment on Google Compute Instance for now.
    2) Assuming that you're performing the following commands under `dlpfilter/` directory.
- To install nodejs, do the following:

      $ chmod +x ./scripts/nodesource_setup.sh
      $ ./scripts/nodesource_setup.sh
- To install Google's fluentd logger agent, do the following:

      $ chmod +x ./scripts/install-logging-agent.sh
      $ ./scripts/install-logging-agent.sh

### how to use dlpfilter
The dlpfilter tool can filter application log messages and other stackdriver logging messages, forwards them to configured stackdriver logging.

- To filter and forward the existing, streaming log messages to stackdriver logging, do the following:

      $ node dlpfilter.js stackdriver-logging files \
            -f <SPACE_SEPARATED_PATHS_TO_FILES> \
            -t <SPACE_SEPARATED_INFOTYPES>

  For example,

      $ node dlpfilter.js stackdriver-logging files \
            -f resources/file1.txt resources/file2.txt \
            -t EMAIL_ADDRESS PHONE_NUMBER

- To filter and forward the another stackdriver log messages to stackdriver logging, do the following:

      $ node dlpfilter.js stackdriver-logging logs \
            -l <SPACE_SEPARATED_STACKDRIVER_LOG_NAMES> \
            -t <SPACE_SEPARATED_INFOTYPES>

  For example,

      $ node dlpfilter.js stackdriver-logging logs \
            -l my-test-log \
            -t EMAIL_ADDRESS PHONE_NUMBER

### feedback:

If you face any issues while following this README file, Please comment in the appropriate section [here](https://trello.com/b/3bUPmJSj/dlpfilter).
