import argparse

from snyk import SnykClient
from utils import get_default_token_path, get_token


def parse_command_line_args():
    parser = argparse.ArgumentParser(description="Snyk API Examples")
    parser.add_argument(
        "--orgId", type=str, help="The Snyk Organisation ID", required=True
    )
    return parser.parse_args()


snyk_token_path = get_default_token_path()
snyk_token = get_token(snyk_token_path)
args = parse_command_line_args()
org_id = args.orgId

client = SnykClient(token=snyk_token)
# for proj in client.organizations.get(org_id).projects.all():
for proj in [client.organizations.get(org_id).projects.get('c88b24fd-e65b-438e-a322-880b07bf2562')]:
    issue_set = proj.issueset.all()
    print(f'project {proj.name}, number of vulnerabilities: {len(issue_set.issues.vulnerabilities)}')
    ignores = proj.ignores.all()
    handled = []
    for issue in issue_set.issues.vulnerabilities:
        if not (issue.isUpgradable or issue.isPinnable or issue.isPatchable):
            if issue.id not in ignores and issue.id not in handled:
                print(f'{issue.__dict__}')
                values_object = {
                    "ignorePath": "",
                    "reasonType": 'temporary-ignore',
                    "disregardIfFixable": True,
                    "reason": "No fix available",
                    "expires": "2030-01-01T12:12:12.000Z"
                }
                api_url = "org/%s/project/%s/ignore/%s" % (org_id, proj.id, issue.id)
                r2 = client.post(api_url, values_object)
                handled.append(issue.id)
        else:
            print(f'Vuln {issue.id} is fixable: {"Upgradable " if issue.isUpgradable else ""} {"Pinnable " if issue.isPinnable else ""} {"Patchable " if issue.isPatchable else ""}')
