# coding=utf-8
import sys
from subprocess import *
import cfg
import os
import xml.dom.minidom
import chardet
import json
import iconv_codecs
from request import Request
import datetime
import time

def scan():
    for target_url in cfg.URL_LIST:
        start_time = datetime.datetime.now() 
        domain = target_url.split('.')[1]
        save_path = cfg.SAVE_PATH + '\\' + domain + '.xml'
        cmd = '"%s" /e /b %s /su "%s" /r /rf %s /rt %s /scan_log /continue /min_severity %s /v' % (
            cfg.CMD_PATH, cfg.SCAN_PATH, target_url, save_path, cfg.type, cfg.level)
        print(cmd)
        p = Popen(cmd,shell=True,stdin=PIPE,stdout=PIPE)
        result = p.stdout.readline()
        while p.poll() is None:
            last_time = datetime.datetime.now() 
            print('scan not completed and spend time: '+str(last_time-start_time))
            time.sleep(5)
        #p.wait()
        if p.returncode == 0 and os.access(save_path, os.F_OK):
            parse(save_path,'')
        else:
            print('Subprocess failed')

def parse(file_path,parent):
    if os.access(file_path, os.F_OK):
        dom = xml.dom.minidom.parse(file_path)
        root = dom.documentElement
        issuetypes = root.getElementsByTagName('IssueType')
        issuess = root.getElementsByTagName('Issue')
        entitylist = []
        for issuetype in issuetypes:
            issueid = issuetype.getAttribute('ID')
            issues = {}
            for issue in issuess:
                issuetypeid = issue.getAttribute('IssueTypeID')
                if issueid == issuetypeid:
                    issues['url'] = issue.getElementsByTagName('Url')[0].childNodes[0].data 
                    cvss = issue.getElementsByTagName('CVSS')[0]
                    for i in cvss.getElementsByTagName('Score'):
                         issues['score'] = i.childNodes[0].data
            report = {}
            detail = ''
            cause = ''
            securityRisk = ''
            affectedProduct = ''
            cwe = ''
            fid = ''
            reference = ''
            fixRecommendation = ''
            report['id'] = issuetype.getElementsByTagName('RemediationID')[0].childNodes[0].data 
            report['name'] = issuetype.getElementsByTagName('name')[0].childNodes[0].data
            report['parentId'] = parent       
            report['desc'] = issuetype.getElementsByTagName('testDescription')[0].childNodes[0].data
            report['severity'] = issuetype.getElementsByTagName('Severity')[0].childNodes[0].data
            report['Invasive'] = issuetype.getElementsByTagName('Invasive')[0].childNodes[0].data
            #classfic = issuetype.getElementsByTagName('threatClassification')
            #if classfic:
            #    classfic = classfic[0]
            #    report['threatClassification'] = classfic.getElementsByTagName('name')[0].childNodes[0].data + classfic.getElementsByTagName('reference')[0].childNodes[0].data
            technical = issuetype.getElementsByTagName('testTechnicalDescription')[0]
            for text in technical.getElementsByTagName('text'):
                detail += text.childNodes[0].data
            report['details'] = detail
            causes = issuetype.getElementsByTagName('causes')[0]
            for i in causes.getElementsByTagName('cause'):
                cause += i.childNodes[0].data
            report['cause'] = cause
            securityRisks = issuetype.getElementsByTagName('securityRisks')[0]
            for i in securityRisks.getElementsByTagName('securityRisk'):
                securityRisk += i.childNodes[0].data
            report['criticality'] = securityRisk
            affectedProducts = issuetype.getElementsByTagName('affectedProducts')[0]
            for i in affectedProducts.getElementsByTagName('affectedProduct'):
                affectedProduct += i.childNodes[0].data
            report['impact'] = affectedProduct
            cwes = issuetype.getElementsByTagName('cwe')
            if cwes:
                cwes = cwes[0]
                for link in cwes.getElementsByTagName('link'):
                    cwe += 'cwe-'+str(link.getAttribute('id'))
            report['tags'] = cwe
            report['affects_url'] = issues['url'] 
            report['cvss_score'] = issues['score']
            report['cvss2'] = ''
            report['cvss3'] = ''
            report['source'] = 'appscan'
            xfid = issuetype.getElementsByTagName('xfid')
            if xfid:
                xfid = xfid[0]
                for link in xfid.getElementsByTagName('link'):
                    fid += link.getAttribute('target') + link.getAttribute('id')
            report['xfid'] = fid
            references = issuetype.getElementsByTagName('references')[0]
            for link in references.getElementsByTagName('link'):
                reference += link.getAttribute('target') + link.getAttribute('id')
            report['references'] = reference
            fixRecommendations = issuetype.getElementsByTagName('fixRecommendations')[0]
            for i in fixRecommendations.getElementsByTagName('fixRecommendation'):
                for text in i.getElementsByTagName('text'):
                    fixRecommendation += text.childNodes[0].data
            report['recommendation']  = fixRecommendation
    else:
        print("there is no file in: "+file_path)

def main():
	try:
		scan()
	except Exception as e:
		print('scan has error',e)
if __name__ == "__main__":
    main()
