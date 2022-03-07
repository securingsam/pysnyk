# SAM Report Generation

## Create report with fixable only

In order to generate a report with only fixable issues run the following:

```shell
python examples/sam-report-ignore-non-fixable.py --orgId=<org ID>
```

Additional Flags:
- projectId - run on specific Project
- disregardIfFixable - surprise all issues even if there is a fix
- forceIgnore - ignore all and bypass all rules.
