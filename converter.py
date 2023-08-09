import datetime as dt
from tkinter import filedialog
from tkinter import *
import matplotlib.pyplot as plt
from docxtpl import DocxTemplate, InlineImage
import pandas as pd
import random
from googletrans import Translator
import requests
from bs4 import BeautifulSoup
import threading

# global mapping objects
risk_mappeur = {
    "Critical": 'Critique',
    "High": "Elevée",
    "Medium": "Moyenne",
    "Low": "Faible",
    "Unknown": "non-fourni"
}
color_mappeur = {
    'Critique': 'red',
    "Elevée": 'orange',
    "Moyenne": "yellow",
    "Faible": "green",
    "non-fourni": "gray"
}
scrappeur_AV = {
    'N': "Réseau",
    'A': "Contigu",
    'L': "Local",
    'P': "Physique",
    'R': "Rien"
}
scrappeur_others = {
    'N': 'Rien',
    "P": "Partielle",
    'M': 'Moyenne',
    'L': "Faible",
    'H': "Elevée",
    "R": "Requis",
    "U": "Inchangé",
    "C": "Modifié"
}

# Those lists are going to be used in the exploitation function to scrap web and check for vul exploitation
exploitation_cols = ["exploited", "exploitedby"]
scrapped_cols = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

# random generator until creating the form
gene = random.randint(1, 1000)

# This is going to be used for the web scraping module
scrapped = {}
link = "https://www.tenable.com/plugins/nessus/"


def fn_scrappeur(plugin_list):
    for plugin in plugin_list:
        req = requests.get(link + str(plugin))
        soup = BeautifulSoup(req.text, "html.parser")
        element = soup.find_all('p')
        element = [item.text for item in element if ("Vector" in item.text) & ("AV" in item.text)]
        element.sort(key=len, reverse=True)
        data_dict = {}
        if element:
            components = element[0].split('/')
            components.pop(0)
            for component in components:
                key, value = component.split(':')
                data_dict[key] = value
        scrapped[plugin] = data_dict


# This is going to be used for web scraping and vul exploitation
def exploitation(row):
    if row.Metasploit | row.CANVAS | row.Core:
        row.exploited = "Vrai"
        new = []
        if row.Metasploit:
            new.append("Metasploit")
        if row.CANVAS:
            new.append("CANVAS")
        if row.Core:
            new.append("Core")
        row.exploitedby = '/'.join(new)
    else:
        row.exploited = "Faux"
        row.exploitedby = "Rien"

    row.AV = scrappeur_AV[scrapped[row.PlugId].get("AV", "R")]
    row.AC = scrappeur_others[scrapped[row.PlugId].get("AC", "N")]
    row.PR = scrappeur_others[scrapped[row.PlugId].get("PR", "N")]
    row.UI = scrappeur_others[scrapped[row.PlugId].get("UI", "N")]
    row.S = scrappeur_others[scrapped[row.PlugId].get("S", "N")]
    row.C = scrappeur_others[scrapped[row.PlugId].get("C", "N")]
    row.I = scrappeur_others[scrapped[row.PlugId].get("I", "N")]
    row.A = scrappeur_others[scrapped[row.PlugId].get("A", "N")]

    return row


def openFile():
    doc = DocxTemplate("./template_data/template1.docx")

    filename = filedialog.askopenfilename(initialdir=".", title="Select a csv File",
                                          filetypes=(("csv files", "*.csv"),))
    csvRows = pd.read_csv(filename)
    csvRows = csvRows.dropna(how='all')
    csvRows = csvRows.rename(
        columns={"CVSS v2.0 Base Score": "Cvss2", "Plugin ID": "PlugId", "See Also": "See", "Plugin Output": "PlugOut",
                 "STIG Severity": "StigSeverity", "CVSS v3.0 Base Score": "Cvss3", "VPR Score": "VRP",
                 "Risk Factor": "RiskFactor", "Plugin Publication Date": "PluginPub",
                 "Plugin Modification Date": "PluginMod", "Core Impact": "Core"})
    csvRows.Cvss2.fillna(-1, inplace=True)
    csvRows.Cvss3.fillna(csvRows["Cvss2"], inplace=True)
    csvRows.RiskFactor.fillna("Unknown", inplace=True)
    csvRows.Risk.fillna("Unknown", inplace=True)
    csvRows.RiskFactor.replace("None", 'Unknown', inplace=True)
    csvRows.Risk.replace("None", 'Unknown', inplace=True)
    csvRows.loc[csvRows['RiskFactor'] == "Unknown", 'RiskFactor'] = csvRows.loc[
        csvRows['RiskFactor'] == "Unknown", 'Risk']
    csvRows["Riskcolor"] = csvRows["RiskFactor"].apply(lambda risk: color_mappeur[risk_mappeur[risk]])

    name_risk = csvRows.groupby("Name")["RiskFactor"].apply(lambda serie: serie.value_counts().index[0]).value_counts()
    name_risk_list = list(name_risk.index)

    # vulnerability bar image
    plt.figure(figsize=(6.4, 4.4))
    x = [risk_mappeur[item] for item in name_risk_list]
    c = [color_mappeur[item] for item in x]
    plt.xlabel("Vulnérabilités", fontsize=12, labelpad=6)
    plt.ylabel("Nbr", fontsize=12, labelpad=10)
    plt.title("Synthèse des Résultats de l’Audit des Vulnérabilités", fontsize=15, color="m")
    plt.bar(x, name_risk, width=0.4, color=c)
    vulbarImg_path = f"./images/vulbarImg_{gene}.png"
    plt.savefig(vulbarImg_path, bbox_inches='tight')

    # vulnerability pie image
    plt.figure(figsize=(6.4, 4))
    x1 = [(x * 100) / sum(name_risk) for x in name_risk]
    plt.pie(x1, labels=x, colors=c, autopct="%0.2f%%", shadow=True, textprops={"fontsize": 12}, pctdistance=0.8)
    plt.pie([1], colors="w", radius=0.63)
    plt.title("Détails de Scan", fontsize=17, color="m")
    vulpieImg_path = f"./images/vulpieImg_{gene}.png"
    plt.savefig(vulpieImg_path, bbox_inches='tight')

    # Top10 impacted hosts
    top_impacted_hosts = csvRows.groupby("Host").Name.unique()
    top_impacted_hosts = top_impacted_hosts.apply(len).reset_index().sort_values(by="Name", ascending=False)
    top_impacted_hosts = top_impacted_hosts["Host"][:10].to_list()

    filtered_csvRows = csvRows[csvRows["Host"].isin(top_impacted_hosts)]
    host_risk = filtered_csvRows.groupby(["Host", "RiskFactor"])["Name"].apply(
        lambda serie: len(serie.unique())).reset_index()
    list_host_risk = host_risk.groupby("RiskFactor").apply(lambda df: df.set_index("Host")["Name"].to_dict()).to_dict()

    # host_vuls bar image
    plt.figure()

    y_axis = []
    y_labels = []
    for key, value in list_host_risk.items():
        y_labels.append(risk_mappeur[key])
        new_list = [value.get(item, 0) for item in top_impacted_hosts]
        y_axis.append(new_list)

    current = [0] * len(top_impacted_hosts)
    plt.xlabel("Nbr", fontsize=12, labelpad=6)
    plt.ylabel("Hôtes", fontsize=12, labelpad=10)
    for label, axis in zip(y_labels, y_axis):
        plt.barh(top_impacted_hosts, axis, left=current, color=color_mappeur[label], label=label)
        current = [a + b for a, b in zip(current, axis)]

    plt.legend()
    plt.title("Scan Vulnérabilités serveurs", fontsize=15, color="m")
    host_vul_barImg = f"./images/host_vul_barImg_{gene}.png"
    plt.savefig(host_vul_barImg, bbox_inches='tight')

    # critical/High vulnerabilities

    vul_filtered = csvRows[csvRows["RiskFactor"].isin(["Critical", "High"])]
    risk_vul = vul_filtered.groupby(["RiskFactor", "Name"]).agg('first').reset_index()
    risk_vul["Hosts"] = vul_filtered.groupby(["RiskFactor", "Name"]).Host.unique().to_list()
    risk_vul["count"] = risk_vul.Hosts.apply(len)
    risk_vul["FewOnes"] = risk_vul["Hosts"].apply(lambda list: '/'.join(list[:3]))
    risk_vul["All"] = risk_vul["Hosts"].apply(lambda list: '/'.join(list))
    risk_vul = risk_vul.drop("Hosts", axis=1)
    risk_vul = risk_vul.sort_values(by=['Cvss3', 'RiskFactor', 'count'], ascending=[False, True, False])
    risk_vul.Cvss3.replace(-1, 'non-fourni', inplace=True)
    risk_vul["RiskFactor"] = risk_vul["RiskFactor"].apply(lambda risk: risk_mappeur[risk])

    # working only on the Top100
    risk_vul = risk_vul.iloc[:100]

    # Translation
    # Keep in mind that this is the cause of any latency since we are connecting to an api,
    # if you want to ignore the translation just comment the two mentioned lines
    translator = Translator()
    source_lang = "en"
    target_lang = 'fr'

    list_to_be_translated = risk_vul.loc[:, ["Description", "Synopsis", "Solution"]]
    list_to_be_translated = list_to_be_translated.stack().tolist()

    # Those are the two lines to be commented if we don't want the translation and would like to speed up the generation
    list_to_be_translated = translator.translate(list_to_be_translated, src=source_lang, dest=target_lang)
    list_to_be_translated = [item.text for item in list_to_be_translated]
    # End the comment here

    list_to_be_translated = [[list_to_be_translated[3 * j + i] for j in range(len(list_to_be_translated) // 3)] for i in
                             range(3)]
    list_to_be_translated = pd.DataFrame({"Description": list_to_be_translated[0], "Synopsis": list_to_be_translated[1],
                                          "Solution": list_to_be_translated[2]})

    risk_vul[["Description", "Synopsis", "Solution"]] = list_to_be_translated[["Description", "Synopsis", "Solution"]]

    # web_scrapping and multithreading

    risk_vul["PlugId"] = risk_vul["PlugId"].astype(int)
    plugin_list = risk_vul["PlugId"].unique()

    # The number of threads
    nbr_threats = 4

    plugin_lists = [plugin_list[i * (len(plugin_list) // nbr_threats): (i + 1) * (len(plugin_list) // nbr_threats)] for
                    i in range(nbr_threats - 1)]
    plugin_lists.append(plugin_list[(nbr_threats - 1) * (len(plugin_list) // nbr_threats):])

    threads = []
    for plugin_list in plugin_lists:
        th = threading.Thread(target=fn_scrappeur, args=(plugin_list,))
        threads.append(th)

    for item in threads:
        item.start()

    for item in threads:
        item.join()

    for scrapped_col in scrapped_cols:
        risk_vul[scrapped_col] = None

    # Exploitation treatment

    risk_vul.Metasploit.fillna(False, inplace=True)
    risk_vul.CANVAS.fillna(False, inplace=True)
    risk_vul.Core.fillna(False, inplace=True)

    for exploitation_col in exploitation_cols:
        risk_vul[exploitation_col] = None

    risk_vul = risk_vul.apply(exploitation, axis='columns')

    # Top10 of risk_vul
    top10risk = risk_vul.iloc[:10].to_dict('records')

    # Top100 of risk_vul
    top100risk = risk_vul.to_dict('records')

    todayStr = dt.datetime.now().strftime("%d-%b-%Y")

    # create context to pass data to template
    context = {
        "gen_date": todayStr,
        "csvRows10": top10risk,
        "csvRows100": top100risk,
        'vulbarImg': InlineImage(doc, vulbarImg_path),
        'vulpieImg': InlineImage(doc, vulpieImg_path),
        'host_vul_barImg': InlineImage(doc, host_vul_barImg)
    }
    doc.render(context)

    # save the document object as a word file
    reportWordPath = f'./rapports/new_rapport_{todayStr}_{gene}.docx'
    doc.save(reportWordPath)

    # close the window when the function finishes its work
    window.destroy()


window = Tk()
window.title("Welcome to Nessus Rapport Generator")
window.geometry("500x50")
button = Button(text="Click Here", command=openFile, width=200, height=50).pack()
window.mainloop()
