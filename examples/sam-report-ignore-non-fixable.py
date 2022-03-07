import argparse
import json

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():

    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument("--orgId", type=str, help="The Snyk Organisation ID", required=True)
    parser.add_argument("--projectId", type=str, help="The project ID in Snyk", required=False, default="")
    parser.add_argument("--disregardIfFixable",  type=bool, help="If there is a fix, dont ignore the issue",
                        required=False, default=False)
    parser.add_argument("--forceIgnore", type=bool, help="Ignore al even if there is a fix",
                        required=False, default=False)
    return parser.parse_args()


def ignore_non_fixable():
    snyk_token_path = get_default_token_path()
    snyk_token = get_token(snyk_token_path)
    args = parse_command_line_args()
    org_id = args.orgId
    client = SnykClient(token=snyk_token)

    if args.projectId == "":
        proj_list = client.organizations.get(org_id).projects.all()
    else:
        proj_list = [client.organizations.get(org_id).projects.get(args.projectId)]
    try:
        for proj in proj_list:
            print(f"Project Name: {proj.name}, ProjectId: {proj.id}")
            body = {
                  "includeDescription": False,
                  "includeIntroducedThrough": False,
                  "filters": {
                    "severities": [
                      "critical",
                      "high",
                      "medium",
                      "low"
                    ],
                    "exploitMaturity": [
                      "mature",
                      "proof-of-concept",
                      "no-known-exploit",
                      "no-data"
                    ],
                    "types": [
                      "vuln",
                      "license"
                    ],
                    "ignored": False,
                    "patched": False,
                    "priority": {
                      "score": {
                        "min": 0,
                        "max": 1000
                      }
                    }
                  }
                }
            data = client.post(f"org/{org_id}/project/{proj.id}/aggregated-issues", body)
            issue_set = json.loads(data.text)

            print(f'project {proj.name}, number of vulnerabilities: {len(issue_set["issues"])}')
            ignores = proj.ignores.all()
            handled = []
            for issue in issue_set["issues"]:
                if (not (issue["fixInfo"]["isUpgradable"] or issue["fixInfo"]["isPinnable"] or issue["fixInfo"]["isPatchable"])) or args.forceIgnore:
                    if issue["id"] not in ignores and issue["id"] not in handled:
                        values_object = {
                            "ignorePath": "*",
                            "reasonType": 'temporary-ignore',
                            "disregardIfFixable": args.disregardIfFixable,
                            "reason": "No fix available",
                            "expires": "2030-01-01T12:12:12.000Z"
                        }
                        api_url = "org/%s/project/%s/ignore/%s" % (org_id, proj.id, issue["id"])
                        print(f"Ignore: {api_url}")
                        r2 = client.post(api_url, values_object)
                        handled.append(issue["id"])
                else:
                    print(f'Vuln {issue["id"]} is fixable: {"Upgradable " if issue["fixInfo"]["isUpgradable"] else ""} {"Pinnable " if issue["fixInfo"]["isPinnable"] else ""} {"Patchable " if issue["fixInfo"]["isPatchable"] else ""}')
    except Exception as ex:
        f = open("demofile2.txt", "w")
        f.write(str(ex))
        f.close()
        print(f"error:  {ex}")


if __name__ == '__main__':

    ignore_non_fixable()
