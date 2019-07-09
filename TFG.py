















          "abuseConfidenceScore": 0,
          "abuseConfidenceScore": 0,
          "countryCode": null
          "countryCode": null
          "error": "Duplicate IP",
          "error": "Invalid Category",
          "error": "Invalid IP",
          "input": "127.0.foo.bar",
          "input": "189.87.146.50",
          "input": "41.188.138.68",
          "ipAddress": "127.0.0.1",
          "ipAddress": "127.0.0.2",
          "mostRecentReport": "2019-03-21T16:35:16+00:00",
          "mostRecentReport": "2019-03-2T20:31:17+00:00",
          "numReports": 16,
          "numReports": 631,
          "parameter": "ip"
          "rowNumber": 5
          "rowNumber": 6
          "rowNumber": 8
        "detail": "You can only report the same IP address (`185.222.209.14`) once in 15 minutes.",
        "source": {
        "status": 429,
        ...
        {
        {
        {
        {
        {
        }
        }
        },
        },
        },
        },
      "abuseConfidenceScore": 100
      "abuseConfidenceScore": 100
      "abuseConfidenceScore": 100
      "abuseConfidenceScore": 16,
      "abuseConfidenceScore": 2
      "addressSpaceDesc": "Loopback",
      "countryCode": "UK",
      "countryName": "Ukraine",
      "domain": "kyivstar.ua",
      "invalidReports": [
      "ipAddress": "118.25.6.39",
      "ipAddress": "178.137.87.242",
      "ipAddress": "185.222.209.14",
      "ipAddress": "222.73.44.146",
      "ipAddress": "81.133.189.239",
      "ipVersion": 4,
      "isp": "Kyivstar PJSC",
      "isPublic": true,
      "isWhitelisted": false,
      "lastReportedAt": "2019-04-18T15:52:14+00:00",
      "maxAddress": "127.0.0.255",
      "minAddress": "127.0.0.1",
      "netmask": "255.255.255.0",
      "networkAddress": "127.0.0.0",
      "numPossibleHosts": 256,
      "reportedAddress": [
      "savedReports": 60,
      "totalReports": 1499,
      "totalReports": 202,
      "totalReports": 2138,
      "totalReports": 38,
      "usageType": "Unknown",
      ]
      ]
      {
      }
    "data": {
    "data": {
    "data": {
    "errors": [
    "generatedAt": "2019-04-18T19:00:04+00:00"
    ...
    ]
    {
    {
    {
    {
    }
    }
    }
    },
    },
    },
   "data": {
  "data": [
  "meta": {
  --data-urlencode "comment=Explaining reasons for reporting" \
  --data-urlencode "ip=185.222.209.14" \
  --data-urlencode "ipAddress=178.137.87.242" \
  -/*
  -d categories=17,21 \
  -d confidenceMinimum=75 \
  -d countMinimum=10 \
  -d maxAgeInDays=30 \
  -d maxAgeInDays=30 \
  -d maxAgeInDays=60 \
  -F csv=@report.csv \
  -H "Accept: application/json"
  -H "Accept: application/json"
  -H "Accept: application/json"
  -H "Accept: application/json"
  -H "Accept: application/json" \
  -H "Key: $YOUR_API_KEY" \
  -H "Key: $YOUR_API_KEY" \
  -H "Key: $YOUR_API_KEY" \
  -H "Key: $YOUR_API_KEY" \
  -H "Key: $YOUR_API_KEY" \
  > output.json
  ]
  curl -G https://api.abuseipdb.com/api/v2/blacklist \
  curl https://api.abuseipdb.com/api/v2/bulk-report \
  {
  {
  }
  }
  }
  }
  },
 --data-urlencode "network=127.0.0.1/24" \
CHECK-BLOCK Endpoint
curl -G https://api.abuseipdb.com/api/v2/check \
curl -G https://api.abuseipdb.com/api/v2/check-block \
curl https://api.abuseipdb.com/api/v2/report \
Reporting 127.0.0.2 will simulate a short term rate limit. This is useful for application testing.
{
{
}9897º1	Q
# :l;KCVFDXSZA<RVHTNYJUKMNMILOÑP´`Ç
+479634201


/api.php?api_key=[API_KEY]&action={getList||getListraw}

  /api.php?api_key=[API_KEY]&action=getfile&hash=[HASH]

  /api.php?api_key=[API_KEY]&action=details&hash=[HASH]

    /api.php?api_key=[API_KEY]&action=type&type=[FILE TYPE] 

    /api.php?api_key=[API_KEY]&action=search&query=[SEARCH QUERY] 

      /api.php?api_key=[API_KEY]&action=upload

        /api.php?api_key=[API_KEY]&action=gettypes


curl -X GET \
  'https://api.metadefender.com/v4/feed/infected?page=1' \
  -H "apikey: ${APIKEY}"


[
    {
        "md5": "9498FF82A64FF445398C8426ED63EA5B",
        "sha1": "36F9CA40B3CE96FCEE1CF1D4A7222935536FD25B",
        "sha256": "8B2E701E91101955C73865589A4C72999AEABC11043F712E05FDB1C17C4AB19A",
        "link": "https://metadefender.opswat.com/results#!/file/bzE5MDIyNkJ5OE9kSUVRTDRTa0R1dVVWWElW/regular?utm_medium=json&utm_source=www&utm_campaign=threat_feeds",
        "total_avs": 37,
        "total_detected_avs": 25,
        "threat_name": "Trojan.Zbot.Win32.21",
        "file_type_category": "E",
        "file_type_extension": "exe",
        "published": "2019-02-26"
    },
    {
        "md5": "CAEF973033E593C625FB2AA34F7026DC",
        "sha1": "D5DD920BE5BCFEB904E95DA4B6D0CCCA0727D692",
        "sha256": "DB1AEC5222075800EDA75D7205267569679B424E5C58A28102417F46D3B5790D",
        "link": "https://metadefender.opswat.com/results#!/file/bzE5MDIyNnIxUXhkR0dGRzhOUzFWeGR6R3RNTEU/regular?utm_medium=json&utm_source=www&utm_campaign=threat_feeds",
        "total_avs": 37,
        "total_detected_avs": 4,
        "threat_name": "Gen:Variant.Barys.11503",
        "file_type_category": "E",
        "file_type_extension": "exe",
        "published": "2019-02-26"
    },
  ...
]


curl -X GET "https://api.maltiverse.com/ip/188.165.210.84" -H  "accept: application/json"

{
  "as_name": "AS16276 OVH SAS",
  "asn_cidr": "188.165.0.0/16",
  "asn_country_code": "FR",
  "asn_date": "2009-06-05 00:00:00",
  "asn_registry": "ripencc",
  "blacklist": [
    {
      "description": "SSH Attacker",
      "first_seen": "2019-04-23 17:58:04",
      "last_seen": "2019-04-23 17:58:04",
      "ref": [
        107
      ],
      "source": "Telefonica CO SOC"
    }
  ],
  "classification": "malicious",
  "country_code": "FR",
  "creation_time": "2019-04-23 17:58:04",
  "ip_addr": "188.165.210.84",
  "location": {
    "lat": 48.8582,
    "lon": 2.3387000000000002
  },
  "modification_time": "2019-04-23 17:58:04",
  "tag": [
    "ssh",
    "bruteforce",
    "bot"
  ],
  "type": "ip",
  "visits": 0
}

curl -X PUT "https://api.maltiverse.com/ip/188.165.210.84" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{ ... }"

=CAMBIAR([@Sources];"Malshare";100;
  "MajesticMillion";0;
  "AbuseIPDB";[@ConfidenceScore]*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));
  "MrLooquer";100*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));
  "FruxLabs";100*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));
  "Maltiverse";SI([@Type]="Malware";100;[@ConfidenceScore]*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60))))

  =SI([@Subtype]="Whitelist";0;CAMBIAR([@Type];"Malware";SI([@Subtype]="Adware";2;3);"IP";SI([@Subtype]="Mail Spammer";1;SI([@Subtype]="Malware";3;2));
    "Url";1;"Hostname";SI([@Subtype]="Malware";3;2)))

  =REDONDEAR([@Impact]*[@Probability]/100;0)+SI([@Subtype]="Whitelist";0;1)

  =SI(CAMBIAR([@Sources];"Malshare";100;"MajesticMillion";0;"AbuseIPDB";[@ConfidenceScore]*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));"MrLooquer";100*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));"FruxLabs";100*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));"Maltiverse";SI([@Type]="Malware";100;[@ConfidenceScore]*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60))))<0;0;CAMBIAR([@Sources];"Malshare";100;"MajesticMillion";0;"AbuseIPDB";[@ConfidenceScore]*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));"MrLooquer";100*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));"FruxLabs";100*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60));"Maltiverse";SI([@Type]="Malware";100;[@ConfidenceScore]*(1-(SI(DIAS(HOY();[@LastDateObserved])<7;0;DIAS(HOY();[@LastDateObserved])-7)/60)))))


  {
  "ID": 1,
  "Feed": "8994a4713713e4683117e35d8689ea24",
  "Type": "Malware",
  "Subtype": null,
  "Sources": "Malshare",
  "LastDateObserved": "1/05/2019",
  "ConfidenceScore": "N/A",
  "Probability": 100,
  "Impact": 3,
  "RS": 4
}

<stix:STIX_Package 
  xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
  xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
  xmlns:indicator="http://stix.mitre.org/Indicator-2"
  xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
  xmlns:stix="http://stix.mitre.org/stix-1"
  xmlns:stixCommon="http://stix.mitre.org/common-1"
  xmlns:cybox="http://cybox.mitre.org/cybox-2"
  xmlns:example="http://example.com"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   id="example:Package-64eba84f-5185-4bbe-83de-a5f71cc197db" version="1.2">
    <stix:STIX_Header>
        <stix:Description>Feeds in STIX format with their Risk Scores</stix:Description>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="example:indicator-b8dea4ab-831f-4905-a462-27a8dfca2a60" timestamp="2019-05-17T13:03:01.485730+00:00" xsi:type='indicator:IndicatorType'>
            <indicator:Title>Feeds and Risk Score</indicator:Title>
            <indicator:Description>An indicator containing the feed and the appropriate Risk Score</indicator:Description>
            <indicator:Observable id="example:Observable-6b8e5775-fdaa-4bef-8ca7-eda6899685bd">
                <cybox:Object id="example:File-33755415-ca58-4c79-9fd2-fac116631d3c">
                    <cybox:Properties xsi:type="FileObj:FileObjectType">
                        <FileObj:Hashes>
                            <cyboxCommon:Hash>
                                <cyboxCommon:Type xsi:type="cyboxVocabs:HashNameVocab-1.0">MD5</cyboxCommon:Type>
                                <cyboxCommon:Simple_Hash_Value>8994a4713713e4683117e35d8689ea24</cyboxCommon:Simple_Hash_Value>
                            </cyboxCommon:Hash>
                        </FileObj:Hashes>
                    </cybox:Properties>
                </cybox:Object>
            </indicator:Observable>
            <indicator:Likely_Impact timestamp="2019-05-17T13:03:01.485730+00:00">
                <stixCommon:Value>Risk Score: 4(Critical)</stixCommon:Value>
            </indicator:Likely_Impact>
            <indicator:Producer>
                <stixCommon:Identity>
                    <stixCommon:Name>Malshare</stixCommon:Name>
                </stixCommon:Identity>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2019-01-05T00:00:00</cyboxCommon:Produced_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
</stix:STIX_Package>

<stix:STIX_Package 
  xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
  xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
  xmlns:stixCommon="http://stix.mitre.org/common-1"
  xmlns:stix="http://stix.mitre.org/stix-1"
  xmlns:indicator="http://stix.mitre.org/Indicator-2"
  xmlns:ta="http://stix.mitre.org/ThreatActor-1"
  xmlns:example="http://example.com"
  xmlns:xlink="http://www.w3.org/1999/xlink"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   id="example:Package-8ce43956-0ea7-4496-98c6-6df13b215b4d" version="1.2">
    <stix:STIX_Header>
        <stix:Description>Feeds in STIX format with their Risk Scores</stix:Description>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="example:indicator-0724322f-5ea6-4f34-b129-d49b9c96b2ef" timestamp="2019-05-17T15:10:56.521894+00:00" xsi:type='indicator:IndicatorType'>
            <indicator:Title>Risk Score</indicator:Title>
            <indicator:Description>An indicator containing the appropriate Risk Score</indicator:Description>
            <indicator:Likely_Impact timestamp="2019-05-17T15:10:56.521894+00:00">
                <stixCommon:Value>Risk Score: 2(Medium)</stixCommon:Value>
            </indicator:Likely_Impact>
            <indicator:Producer>
                <stixCommon:Time>
                    <cyboxCommon:Produced_Time>2019-01-05T00:00:00</cyboxCommon:Produced_Time>
                </stixCommon:Time>
            </indicator:Producer>
        </stix:Indicator>
    </stix:Indicators>
    <stix:Threat_Actors>
        <stix:Threat_Actor id="example:threatactor-8207bab2-8636-4193-8d15-57d941b0767b" timestamp="2019-01-05T00:00:00" xsi:type='ta:ThreatActorType'>
            <ta:Title>Ip/Domain/Hostname</ta:Title>
            <ta:Description>A threatActor commited with malicious tasks</ta:Description>
            <ta:Identity id="106.113.123.197"/>
            <ta:Type timestamp="2019-05-17T15:10:56.521894+00:00">
                <stixCommon:Value xsi:type="stixVocabs:ThreatActorTypeVocab-1.0">eCrime Actor - Spam Service</stixCommon:Value>
            </ta:Type>
            <ta:Information_Source>
                <stixCommon:Description>Malshare</stixCommon:Description>
            </ta:Information_Source>
        </stix:Threat_Actor>
    </stix:Threat_Actors>
</stix:STIX_Package>
'