import argparse
import subprocess
from multiprocessing import Process, Queue
from vol_bot import Vol_Bot
from section_api import Section
import pdb



Plugin_List = ['pslist', 'psscan', 'modules', 'dlllist', 'cmdline', 'svcscan', 'handles', 'netscan']

def execute_pslist(vol_engine, pqueue):
    return vol_engine.pslist()


def execute_psscan(vol_engine, pqueue):
    psscan_output = vol_engine.pslist()
    pqueue.put(psscan_output)


def execute_process_finder(vol_engine, pqueue):
    return




#def determine_profile(vol_engine):
#    profile_output = subprocess.run([vol_engine.vol_loc, vol_engine.memory_file, "kdbgscan"], capture_output=True, text=True)
#    print(profile_output)


def generate_html(sections_list):
    html_text = "<html>" +"<head>"+"<style>"
    html_text += ".collapsible{background-color: #777; color: white; cursor: pointer;\
    padding: 18px;width: 100%;border: none;text-align: left;outline: none;font-size: 15px;}"
    html_text += ".content{padding: 0 18px;display: none;overflow: hidden;background-color: #f1f1f1;}"
    html_text += ".active, .collapsible:hover {background-color: #555;}"
    html_text += ".collapsible:after {content: '\002B';color: white;font-weight: bold;float: right;margin-left: 5px;}"
    html_text += ".active:after {content: '\2212';}"
    html_text += "table, th, td {border: 1px solid black;border-collapse: collapse;border-spacing:8px}"
    html_text += "</style>" + "</head>" + "<body>"
    for sec in sections_list:
        html_text += "<table style='width:50%'>"
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
            #html_text += "<button type='button' class='collapsible'>" + str(item['Name'])
            #html_text += "<div class='content'>" + str("<p><b>Process:</b> " + item['Process'] + " <br><b>Name:</b> " + item['Name'] + " <br><b>Path:</b> " + item['Path']) + "</p></div><br>"
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
        #html_text += "<script>var coll = document.getElementsByClassName('collapsible');var i;for (i = 0; i < coll.length; i++) {\
        #    coll[i].addEventListener('click', function() {this.classList.toggle('active');var content = this.nextElementSibling;\
        #        if (content.style.display === 'block') {content.style.display = 'none';} else {content.style.display = 'block';}});}</script>"
    html_text += "</body>" + "</html>"
    f = open("report.html", "w")
    f.write(html_text)
    f.close()




def main():
    parser = argparse.ArgumentParser(description='Autovolatile Stuff')
    parser.add_argument('-l', '--location', action='store', required=True)
    parser.add_argument('-f', '--file', action='store')
    #parser.add_argument('-p', '--profile', action='store')
    args = parser.parse_args()

    vol_engine = Vol_Bot(args.file, args.location)
    output_dict = {}
    #pqueue = Queue()
    
    
    
    #for item in Plugin_List:
    #    if item == 'pslist':
    #        p = Process(target=execute_pslist, args=[vol_engine, pqueue])
    #        p.start()
        #elif item == 'psscan':
        #    p = Process(target=execute_psscan(pqueue))
        #elif item == 'modules':
        #    p = Process(target=execute_modules(pqueue))

    
    output_dict['pslist'] = vol_engine.pslist()
    output_dict['psscan'] = vol_engine.psscan()
    output_dict['dlllist'] = vol_engine.dlllist()
    output_dict['modules'] = vol_engine.modules()
    output_dict['cmdline'] = vol_engine.cmdline()
    output_dict['svcscan'] = vol_engine.svcscan()
    output_dict['handles'] = vol_engine.handles()
    output_dict['netscan'] = vol_engine.netscan()
    #print(output_dict['psscan'])
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

    generate_html(sections_list)

    

    

    
    #output_dict['dlllist'] = vol_engine.dlllist()
    
    





if __name__ == '__main__':
    main()