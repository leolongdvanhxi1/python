from bs4 import BeautifulSoup

def get_next_p_after_strong(html_file):
    with open(html_file, "r", encoding="latin") as file:
        html_data = file.read()

    soup = BeautifulSoup(html_data, "html.parser")

    paragraphs = soup.find_all("strong")
    text = []
    for p in paragraphs:
        if p.text == "Rule ID:":
            h3 = p.find_previous_sibling("h3")
            if h3:
                h3_value = h3.text.strip()
                next_p = p.find_next_sibling("p")
                if next_p:
                    text.append((h3_value, next_p.text.strip()))
    return text

def rule(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        html_content = file.read()
    soup = BeautifulSoup(html_content, 'html.parser')
    pingcastle_ids = []
    grade_values = []

    pingcastle_elements = soup.find_all('div', class_='row')
    for span in pingcastle_elements:
        pingcastle_p = span.find('p')
        if pingcastle_p and 'PingCastle ID' in pingcastle_p.text:
            pingcastle_spans = pingcastle_p.find_all('span', class_='text-monospace')
            pingcastle_ids.extend(span for span in pingcastle_spans)

    for span in pingcastle_ids:
        if span:
            pingcastle_id = span
            grade_spans = []
            div = span.find_parent('div', class_='row')
            for _ in range(3):
                if div:
                    grade_spans += div.find_all('span', class_=lambda value: value and value.startswith('badge grade-'))
                    div = div.find_previous_sibling('div', class_='row')
            grade_values.append([int(span.text) for span in grade_spans])
            if pingcastle_id not in pingcastle_ids:
                pingcastle_ids.append(pingcastle_id)

    output = {}
    for i in range(len(pingcastle_ids)):
        output[pingcastle_ids[i].text] = grade_values[i]

    return output

def Techniques(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    soup = BeautifulSoup(html_content, 'html.parser')
    elements = soup.find_all(['strong', 'span', 'h3'])
    output = {}

    given_titles = ['Initial Access', 'Execution', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement']
    current_title = None
    current_values = []
    for element in elements:
        if element.name == 'strong':
            title = element.text.strip()
            if title in given_titles:
                if current_title is not None:
                    output[current_title] = current_values
                current_title = title
                current_values = []
        elif element.name == 'span':
            if current_title is not None:
                value = element.text.strip()
                current_values.append(value)
        elif element.name == 'h3':
            if current_title is not None:
                output[current_title] = current_values
            current_title = None
            current_values = []

    if current_title is not None:
        output[current_title] = current_values

    return output

ad_hc_ais_values = get_next_p_after_strong("check.html")
rule_values = rule("rule.html")
tech = Techniques("rule.html")

severity_map = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low"
}

sorted_values = sorted(set(ad_hc_ais_values), key=lambda x: (severity_map.get(rule_values.get(x[1], [0])[0], ""), x[0]))

output = ""

for value in sorted_values:
    if value[1] in rule_values:
        severity_values = rule_values[value[1]]
        for severity in severity_values:
            if severity in severity_map:
                pingcastle_id = value[1].ljust(30)  
                name = value[0].ljust(120)  
                level = severity_map[severity]  
                output += f"{pingcastle_id}{name}{level}\n"
with open("text.txt", "w", encoding="utf-8") as file:
    file.write("PingcastleID                  Name                                 \t\t\t\t\t\t\t\t\t\t\tLevel\n\n")
    file.write(output)



