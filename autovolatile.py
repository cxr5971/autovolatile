#Author: Cullen Rezendes
#File Name: autovolatile.py
#Description: autovolatile takes a memory file and vol.py file location and automatically runs a selection of volatility plugins
#   on the dump (pslist, psscan, dlllist, cmdline, svcscan, handles, netscan, modules). Finally, an html report is generated

import argparse
import subprocess
import os
import time
from multiprocessing import Process, Queue
from vol_bot import Vol_Bot
from section_api import Section






    #Function: generate_html
    #Parameters: sections_list (list of process sections to include on report), svcdict (dictionary of services to include at top of report)
    #   moddict (dictionary of modules to include at top of report), mem_file (the mem file we are analyzing, to print to screen at the end)
    #Description: This (disgusting) function adds all of the Vol content that has been parsed, into the report. It also attempts to combine the information
    #   meaning that data from different plugins with the same PID and other attributes will be placed together!
    #Returns: None, creates report.html file
def generate_html(sections_list, svcdict, moddict, mem_file):
    html_text = "<html>" +"<head>"+"<style>"
    html_text += ".collapsible{background-color: #777; color: white; cursor: pointer;\
    padding: 18px;width: 100%;border: none;text-align: left;outline: none;font-size: 15px;}"
    html_text += ".content{padding: 0 18px;display: none;overflow: hidden;background-color: #f1f1f1;}"
    html_text += ".active, .collapsible:hover {background-color: #555;}"
    html_text += ".collapsible:after {content: '\002B';color: white;font-weight: bold;float: right;margin-left: 5px;}"
    html_text += ".active:after {content: '\2212';}"
    html_text += "table, th, td {border: 1px solid black;border-collapse: collapse;border-spacing:8px}"
    html_text += "h1 {text-align: center;}"
    html_text += ".center {margin-left: auto; margin-right: auto;}"
    html_text += "</style>" + "</head>" + "<body>"
    html_text += "<h1>AutoVolatile Report: " + str(mem_file) + "</h1>"
    html_text += "<table class='center' style='width:50%'"
    html_text += "<tr>"
    html_text += "<td><b>modules</b>:</td>"
    html_text += "<td>"
    html_text += "<details><summary>Expand Modules List</summary>"
    for module_entry in moddict:
        for mod in module_entry:
            html_text += "<details><summary>" + str(module_entry[mod]['Name']) +"</summary>"
            html_text += str("<p><b>Offset:</b> "+ str(module_entry[mod]['Offset']) + "<br><b>Name:</b> " + str(module_entry[mod]['Name'])) + "<br><b>Path:</b> " +str(module_entry[mod]['Path']) + "<br><b>FileOutput:</b> "\
                +str(module_entry[mod]['FileOutput'])
            html_text += "</details>"
    html_text += "</details>"
    html_text += "</tr></table><br><br><br>"
    html_text += "<table class='center' style='width:50%'"
    html_text += "<tr>"
    html_text += "<td><b>services</b>:</td>"
    html_text += "<td>"
    html_text += "<details><summary>Expand Serv List</summary>"
    for svc_entry in svcdict:
        for svc in svc_entry:
            html_text += "<details><summary>" + str(svc_entry[svc]['Name']) +"</summary>"
            html_text += str("<p><b>Offset:</b> "+ str(svc_entry[svc]['Offset']) + "<br><b>PID:</b> " + str(svc_entry[svc]['PID'])) + "<br><b>Start:</b> " +str(svc_entry[svc]['Start']) + "<br><b>State:</b> "\
                +str(svc_entry[svc]['State']) +  "<br><b>Type:</b>" + str(svc_entry[svc]['Type']) + "<br><b>Name:</b>" + str(svc_entry[svc]['Name']) + "<br><b>Display:</b>"\
                    +str(svc_entry[svc]['Display']) + "<br><b>Binary:</b>" + str(svc_entry[svc]['Binary'])
            html_text += "</details>"
    html_text += "</details>"
    html_text += "</tr></table><br><br><br>"
    for sec in sections_list:
        html_text += "<table class='center' style='width:50%'>"
        html_text += "<tr>"
        html_text += "<td>" + "<b>Name</b>:" + "</td>"
        html_text += "<td>" + str(sec.name) + "</th>"
        html_text += "</tr>"
        html_text += "<tr>"
        html_text += "<td>" + "<b>pid</b>:" + "</td>"
        html_text += "<td>" + str(sec.pid) + "</th>"
        html_text += "</tr>"
        html_text += "<tr>"
        html_text +="<td>" + "<b>offset</b>:" + "</td>"
        html_text +="<td>" + str(sec.offset) + "</th>"
        html_text += "</tr>"
        html_text += "<tr>"
        html_text += "<td>" + "<b>network</b>:" + "</td>"
        html_text += "<td>"
        for item in sec.network:
            html_text += str("<b>LocalAddr:</b> " + item['LocalAddr'] + ":" + item['LocalPort']\
                 + " -> <b>ForeignAddr:</b> " + item['ForeignAddr'] + ":" + item['ForeignPort'] + " Owner: " + item['Owner']) + "<br>"
        html_text += "</tr>"
        html_text += "<tr>"
        html_text += "<td>" + "<b>dlls</b>:" + "</td>"
        html_text += "<td>"
        for item in sec.dlls:
            html_text += "<details><summary>" + str(item['Name']) +"</summary>" + str("<b>Process:</b> " + item['Process'] + " <br><b>Name:</b> " + item['Name'] + " <br><b>Path:</b> " + item['Path'])
            html_text += "</details>"
        html_text += "</tr>"
        html_text += "<tr>"
        html_text += "<td>" + "<b>cmdline</b>:" + "</td>"
        html_text += "<td>"
        for item in sec.cmdline:
            html_text += str("<b>Process:</b> " + item['Process'] + " <b>Args:</b> " + item['Args']) + "<br>"
        html_text += "</tr>"
        html_text += "<tr>"
        html_text += "<td>" + "<b>handles</b>:" + "</td>"
        html_text += "<td>"
        handles_dict = {}
        html_text += "<details><summary>Expand List (they can usually be very long)</summary>"
        for item in sec.handles:
            if handles_dict.get(str(item['GrantedAccess'])+str(item['Name'])) != None:
                continue
            temp = item['Name']
            if temp == "":
                temp = 'Name Not Found'
            html_text += "<details><summary>" + str(temp) +"</summary>" + str("<p><b>Process:</b> " \
                + item['Process'] + "<br><b>HandleValue:</b> " + str(item['HandleValue'])) + "<br><b>Type:</b> " +str(item['Type']) + "<br><b>Name:</b> "\
                     +str(temp)
            html_text += "</details>"
        html_text += "</details>"
        html_text += "</tr>"
        html_text += "</table>"
        html_text += "<br><br><br>"
    html_text += "</body>" + "</html>"
    f = open("report.html", "w")
    f.write(html_text)
    f.close()



    #Function: main
    #Parameters: None
    #Description: Takes cmd args (file = memfile, location = vol.py location)
    #Returns: Executes, parses, and relates Vol data into an html report for the analyst
def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(description='Autovolatile Stuff')
    parser.add_argument('-l', '--location', action='store', required=True)
    parser.add_argument('-f', '--file', action='store')
    #parser.add_argument('-p', '--profile', action='store')
    args = parser.parse_args()
    print("Running AutoVolatile")
    print("This may take a bit...")

    #Create a new vol bot to process each vol plugin
    vol_engine = Vol_Bot(args.file, args.location)
    output_dict = {}
    output_dict['pslist'] = vol_engine.pslist()
    output_dict['psscan'] = vol_engine.psscan()
    output_dict['dlllist'] = vol_engine.dlllist()
    output_dict['modules'] = vol_engine.modules()
    output_dict['cmdline'] = vol_engine.cmdline()
    output_dict['svcscan'] = vol_engine.svcscan()
    output_dict['handles'] = vol_engine.handles()
    output_dict['netscan'] = vol_engine.netscan()

    #Create sections to be placed on the report, essentially, extract the data from each plugin dict into its corresponding section
    sections_list = []
    for item in output_dict['psscan']:
        for d in item.keys():
            new_sec = Section(d, item[d]['Offset'])
            new_sec.set_process_info(item[d])
            new_sec.name = item[d]['ImageFileName']
            sections_list.append(new_sec)
    for item in output_dict['dlllist']:
        for d in item.keys():
            for sec in sections_list:
                if sec.pid == item[d]['PID']:
                    sec.dlls.append(item[d])
    for item in output_dict['cmdline']:
        for d in item.keys():
            for sec in sections_list:
                if sec.pid == item[d]['PID']:
                    sec.cmdline.append(item[d])
    for item in output_dict['svcscan']:
        for d in item.keys():
            for sec in sections_list:
                if item[d]['Name'] in sec.process_info['ImageFileName'] or item[d]['Display'] in sec.process_info['ImageFileName']:
                    sec.services.append(item[d])
    for item in output_dict['handles']:
        for d in item.keys():
            for sec in sections_list:
                if item[d]['Process'] in sec.process_info['ImageFileName'] or item[d]['PID'] in sec.process_info['PID']:
                    sec.handles.append(item[d])
    for item in output_dict['netscan']:
        for d in item.keys():
            for sec in sections_list:
                if item[d]['Offset'] in sec.process_info['Offset'] or item[d]['PID'] in sec.process_info['PID']:
                    sec.network.append(item[d])

    #Generate the html report
    generate_html(sections_list, output_dict['svcscan'], output_dict['modules'], args.file)

    
    #Print the time and path of report
    print("Report Generated! Path: " + str(os.getcwd()) + str("/report.html"))
    print("--- %s seconds ---" % (time.time() - start_time))





if __name__ == '__main__':
    main()