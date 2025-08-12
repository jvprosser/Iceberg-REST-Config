#!/bin/bash 

DL_NAME="jvp1-aw-dl"

# If this is an EDL, use the load-balancer hostname instead of the service specific  hostname
RANGER_HOST="XXX.cloudera.site"
HMS_HOST="XXX.cloudera.site"
KNOX_HOST="XXX.cloudera.site"
cdpadmin_user="ZZZ"
cdpadmin_group="ZZZn"
cdpadmin_passwd="XXXXXXXXXX"
EMAIL_ID="foo@bar.com"
ROLE_OF_CLIENT_ID="IcebergAccessRole"
DATABASE="TEST"
ICEBERG_TABLE="EMPLOYEE"

echo "Consider increasing this value to 100 from 10 for testing purposes."
echo "Knox Token Integration - User Limit"
echo "gateway.knox.token.limit.per.user"
echo
echo

echo "name"
echo "providerConfigs:cdp-share-access-providers"
echo "value"
echo "role=federation#federation.name=JWTProvider#federation.enabled=true#federation.param.knox.token.exp.server-managed=true#role=identity-assertion#identity-assertion.name=Default#identity-assertion.enabled=true#identity-assertion.param.group.mapping.$PRIMARY_GROUP=(not (member username))"
echo ""
echo "name"
echo "cdp-share-access"
echo "value"
echo "providerConfigRef=cdp-share-access-providers#KNOXTOKEN:knox.token.ttl=36000000#KNOXTOKEN:knox.token.exp.server-managed=true#KNOXTOKEN:gateway.knox.token.limit.per.user=-1#HMS-API:url=http://${HMS_HOST}:8090"
echo ""

echo "name"
echo "providerConfigs:cdp-share-management-providers"
echo "value"
echo "role=authentication#authentication.name=ShiroProvider#authentication.param.main.invalidRequest=org.apache.shiro.web.filter.InvalidRequestFilter#authentication.param.main.invalidRequest.blockBackslash=false#authentication.param.main.invalidRequest.blockNonAscii=false#authentication.param.main.invalidRequest.blockSemicolon=false#authentication.param.main.pamRealm=org.apache.knox.gateway.shirorealm.KnoxPamRealm#authentication.param.main.knoxAnonFilter=org.apache.knox.gateway.filter.AnonymousAuthFilter#authentication.param.urls./knoxtoken/api/v1/jwks.json=knoxAnonFilter#authentication.param.main.pamRealm.service=login#authentication.param.sessionTimeout=30#authentication.param.urls./**=authcBasic#role=identity-assertion#identity-assertion.name=HadoopGroupProvider#identity-assertion.param.hadoop.proxyuser.impersonation.enabled=true#identity-assertion.param.hadoop.proxyuser.${cdpadmin_user}.users=*#identity-assertion.param.hadoop.proxyuser.${cdpadmin_user}.groups=*#identity-assertion.param.hadoop.proxyuser.${cdpadmin_user}.hosts=*#identity-assertion.param.CENTRAL_GROUP_CONFIG_PREFIX=gateway.group.config.#role=authorization#authorization.name=XASecurePDPKnox#authorization.enabled=false#role=ha#ha.name=HaProvider#ha.enabled=true#ha.param.RANGER=enableStickySession=false;noFallback=false;enableLoadBalancing=true"
echo ""

echo "name"
echo "cdp-share-management"
echo "value"
echo "providerConfigRef=cdp-share-management-providers#RANGER:url=https://${RANGER_HOST}:6182#KNOXTOKEN:knox.token.ttl=-1#KNOXTOKEN:knox.token.type=JWT#KNOXTOKEN:knox.token.target.url=cdp-proxy-token#KNOXTOKEN:knox.token.audiences=cdp-proxy-token#KNOXTOKEN:knox.token.client.data=homepage_url=homepage/home?profile=token&amp;topologies=cdp-proxy-token#KNOXTOKEN:knox.token.exp.tokengen.allowed.tss.backends=JDBCTokenStateService,AliasBasedTokenStateService#KNOXTOKEN:knox.token.lifespan.input.enabled=true#KNOXTOKEN:knox.token.user.limit.exceeded.action=RETURN_ERROR#KNOXTOKEN:knox.token.exp.server-managed=true"
echo ""

echo ""

cat <<EOF
Go to Cloudera Manager > Knox > Configuration.
Select the Knox IDBroker scope.
Edit the Knox IDBroker Advanced Configuration Snippet (Safety Valve) for conf/cdp-resources.xml property:
EOF

echo "name"
echo "sessionPolicyTemplate:read-only"
echo "value"
cat << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListingOfDataLakeFolder",
      "Effect": "Allow",
      "Action": [
        "s3:GetAccelerateConfiguration",
        "s3:GetAnalyticsConfiguration",
        "s3:GetBucketAcl",
        "s3:GetBucketCORS",
        "s3:GetBucketLocation",
        "s3:GetBucketLogging",
        "s3:GetBucketNotification",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketRequestPayment",
        "s3:GetBucketTagging",
        "s3:GetBucketVersioning",
        "s3:GetBucketWebsite",
        "s3:GetEncryptionConfiguration",
        "s3:GetInventoryConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:GetMetricsConfiguration",
        "s3:GetObject",
        "s3:GetObjectAcl",
        "s3:GetObjectTagging",
        "s3:GetObjectVersion",
        "s3:GetObjectVersionAcl",
        "s3:GetObjectVersionTagging",
        "s3:GetReplicationConfiguration",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": "arn:aws:s3:::${bucket}",
          "Condition": {
                  "StringEquals": {
                          "s3:prefix": [
                                  "${prefix}",
                                  "${prefix}/*"
                          ]
                  }
          }

    }
  ]
}
EOF

echo ""
echo ""
echo "Creating Data Share - Registering external clients in CDP"

cat <<EOF
Cloudera Manager UI > Knox > Configuration
Knox Service Advanced Configuration Snippet (Safety Valve) for conf/gateway-site.xml
EOF

echo "name"
echo "gateway.knox.admin.users"
echo "value"
echo "${cdpadmin_user}"
read -p "\nRESTART THE CM SERVCES AND THEN HIT ENTER TO CONTINUE: " variable_name

echo "Create CLIENT_ID / SECRET:"
echo "executing"
set -o xtrace
curl -k -u "${cdpadmin_user}:${cdpadmin_passwd}" "https://${KNOX_HOST}:8443/${DL_NAME}/cdp-share-management/knoxtoken/api/v1/token?doAs=external.user&comment=IcebergRockss&md_contact=${EMAIL_ID}&md_role=${ROLE_OF_CLIENT_ID}&md_type=CLIENT_ID" > CLIENT_ID.json

CLIENT_INFO=`cat CLIENT_ID.json |  jq -r '"export CLIENT_ID=\(.token_id)\nexport SECRET=\(.passcode)\n"'`
eval ${CLIENT_INFO}
echo "CLIENT_ID = ${CLIENT_ID}"
echo "SECRET=${SECRET}"
set +o xtrace

echo 

echo "Create CLIENT_ID as a group In Ranger:"
echo "executing"
set -o xtrace
curl -k -u "${cdpadmin_user}:${cdpadmin_passwd}" -H "Accept: application/json" -H "Content-Type: application/json" -X POST "https://${KNOX_HOST}:8443/${DL_NAME}/cdp-share-management/ranger/service/xusers/groups/" -d "{\"name\": \"${CLIENT_ID}\", \"description\": \"group representing a share for a CLIENT_ID\"}"
set +o xtrace

echo

echo "Create a new  Role and add created Group to the Role in Ranger"
echo "executing"
set -o xtrace
curl -k -u "${cdpadmin_user}:${cdpadmin_passwd}" -H "Accept: application/json" -H "Content-Type: application/json" -X POST  "https://${KNOX_HOST}:8443/${DL_NAME}/cdp-share-management/ranger/service/public/v2/api/roles/" -d "{ \"name\": \"${ROLE_OF_CLIENT_ID}\", \"description\": \"${ROLE_OF_CLIENT_ID} description\", \"groups\": [ { \"name\": \"${CLIENT_ID}\", \"isAdmin\": false } ] }"

set +o xtrace

echo "Confrim by going to https://${KNOX_HOST}:443/${DL_NAME}/cdp-proxy/ranger/#/users/roletab"

echo 
echo "Add a Group to existing Role"
echo "executing"
set -o xtrace
curl -k -u "${cdpadmin_user}:${cdpadmin_passwd}" -H "Accept: application/json" -H "Content-Type: application/json" -X GET  "https://${KNOX_HOST}:8443/${DL_NAME}/cdp-share-management/ranger/service/public/v2/api/roles/name/${ROLE_OF_CLIENT_ID}" > GROUP_ID.json

GROUP_ID_INFO=`cat GROUP_ID.json | jq -r '"export RoleId=\(.id)"'`
#GROUPS_INFO=`cat GROUP_ID.json | jq -r '"\(.groups)\"'`
GROUPS_INFO=`cat GROUP_ID.json | jq -r '"\(.groups)"' | sed -e 's/"/\\\"/g' -e 's/^/export KGROUPS="/' -e 's/$/"/'`


eval ${GROUP_ID_INFO}
eval ${GROUPS_INFO}
echo "RoleId=${RoleId}"
echo "KGROUPS=${KGROUPS}"
set +o xtrace
echo "Add new Group to the Role:"
echo "executing"
set -o xtrace
curl -k -u "${cdpadmin_user}:${cdpadmin_passwd}" -H "Accept: application/json" -H "Content-Type: application/json" -X PUT  "https://${KNOX_HOST}:8443/${DL_NAME}/cdp-share-management/ranger/service/public/v2/api/roles/${RoleId}"  -d "{\"name\": \"${ROLE_OF_CLIENT_ID}\", \"description\": \"${ROLE_OF_CLIENT_ID} description\", \"groups\":\"[${KGROUPS}]\"}"


set +o xtrace
echo "API to a DataShare Policy for the Role in Ranger:"

echo "executing"
set -o xtrace
curl -k -u "${cdpadmin_user}:${cdpadmin_passwd}" -H "Accept: application/json" -H "Content-Type: application/json" -X POST  "https://${KNOX_HOST}:8443/${DL_NAME}/cdp-share-management/ranger/service/public/v2/api/policy/" -d  "{\"service\":\"cm_hive\", \"policyType\": 0, \"name\": \"Iceberg Table Policy\", \"description\": \"Policy for SELECT access to an CLIENT_ID\", \"isEnabled\": true, \"resources\": { \"database\": { \"values\": [\"${DATABASE}\"] }, \"table\": { \"values\": [\"${ICEBERG_TABLE}\"] } ,\"column\": { \"values\": [\"*\"] } } , \"policyItems\": [ { \"accesses\": [ { \"type\": \"select\" } ], \"users\": [], \"groups\":[], \"roles\": [\"${ROLE_OF_CLIENT_ID}\"], \"conditions\": [] } ] }"


set +o xtrace

echo "display Database"

AT=$(curl -k -X POST -H  "Content-Type: application/x-www-form-urlencoded" -d "client_id=${CLIENT_ID}&client_secret=${SECRET}&grant_type=client_credentials" "https://${KNOX_HOST}/${DL_NAME}/cdp-share-access/hms-api/icecli/v1/oauth/tokens" | jq -r '.access_token')

curl -ivk -X GET -H "Content-Type: application/x-www-form-urlencoded" -H "Authorization: Bearer ${AT}" https://${KNOX_HOST}/${DL_NAME}/cdp-share-access/hms-api/icecli/v1/namespaces
echo "DONE"
