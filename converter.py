import datetime as dt
from tkinter import filedialog
from tkinter import *
import matplotlib.pyplot as plt
from docxtpl import DocxTemplate, InlineImage
import pandas as pd
import random
from googletrans import Translator

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

# this is going to be used to check if a it's possible to exploit a certain vulnerability
# look for the Exploitation treatment for further details
exploi_state = []
exploi_details = []

# random generator until creating the form
gene = random.randint(1, 1000)


def exploitation(row):
    if row.Metasploit | row.CANVAS | row.Core:
        exploi_state.append("Vrai")
        new = []
        if row.Metasploit:
            new.append("Metasploit")
        if row.CANVAS:
            new.append("CANVAS")
        if row.Core:
            new.append("Core")
        exploi_details.append('/'.join(new))
    else:
        exploi_state.append("Faux")
        exploi_details.append("Rien")


def openFile():
    doc = DocxTemplate("./template_data/template.docx")

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
    plt.savefig(vulbarImg_path)

    # vulnerability pie image
    plt.figure(figsize=(6.4, 3.5))
    x1 = [(x * 100) / sum(name_risk) for x in name_risk]
    plt.pie(x1, labels=x, colors=c, autopct="%0.2f%%", shadow=True, textprops={"fontsize": 12}, pctdistance=0.8)
    plt.pie([1], colors="w", radius=0.63)
    plt.title("Détails de Scan", fontsize=17, color="m")
    vulpieImg_path = f"./images/vulpieImg_{gene}.png"
    plt.savefig(vulpieImg_path)

    # Top10 impacted hosts
    top_impacted_hosts = csvRows.groupby("Host").Name.unique()
    top_impacted_hosts = top_impacted_hosts.apply(len).reset_index().sort_values(by="Name", ascending=False)
    top_impacted_hosts = top_impacted_hosts["Host"][:10].to_list()

    filtered_csvRows = csvRows[csvRows["Host"].isin(top_impacted_hosts)]
    host_risk = filtered_csvRows.groupby(["Host", "RiskFactor"])["Name"].apply(
        lambda serie: len(serie.unique())).reset_index()
    list_host_risk = host_risk.groupby("RiskFactor").apply(lambda df: df.set_index("Host")["Name"].to_dict()).to_dict()

    # host_vuls bar image
    plt.figure(figsize=(6.4, 4.5))

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
    plt.savefig(host_vul_barImg)

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

    # Exploitation treatment

    risk_vul.Metasploit.fillna(False, inplace=True)
    risk_vul.CANVAS.fillna(False, inplace=True)
    risk_vul.Core.fillna(False, inplace=True)

    risk_vul.apply(exploitation, axis='columns')
    risk_vul["exploited"] = exploi_state
    risk_vul["exploitedby"] = exploi_details

    # Top10 of risk_vul
    top10risk = risk_vul.iloc[:10].to_dict('records')

    # Top100 of risk_vul
    top100risk = risk_vul.iloc[:100].to_dict('records')

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
