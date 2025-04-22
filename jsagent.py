from dotenv import load_dotenv
from datetime import datetime
from crewai import Crew, LLM, Task, Agent
from langchain_openai import ChatOpenAI
from termcolor import colored
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter

import sys, os
import pyfiglet

def clear_terminal():
    os.system("cls" if os.name == "nt" else "clear")

def display_banner():
    ascii_banner = pyfiglet.figlet_format("Js Agent", font="big")
    print(colored(ascii_banner, "red"))
    print(colored("                                        by yee-yore", "magenta"))
    print("\n")
    print("JsAgent is a LLM-powered agent for automated analysis of JS file in bug hunting & pentesting.")
    print(colored("[Ver] Current JsAgent version is v1.0", "cyan"))
    print("=" * 90)

def verify_api_key(llm_type):
    required_keys = ["SERPER_API_KEY"]

    if llm_type == "openai":
        required_keys.append("OPENAI_API_KEY")
    elif llm_type == "anthropic":
        required_keys.append("ANTHROPIC_API_KEY")
    elif llm_type == "gemini":
        required_keys.append("GEMINI_API_KEY")

    load_dotenv()

    missing_keys = [key for key in required_keys if not os.getenv(key)]
    if missing_keys:
        print("🚨 Missing required API keys:")
        for key in missing_keys:
            print(f"   ❌ {key} is not set")
        print("\nPlease check your .env file and set the missing keys.")
        sys.exit(1)

def select_llm():
    ClaudeHaiku = LLM(
        api_key=os.getenv('ANTHROPIC_API_KEY'),
        model='anthropic/claude-3-5-haiku-20241022',
    )

    GPT4oMini = ChatOpenAI(
        model_name="gpt-4o-mini-2024-07-18", 
        temperature=0
    )

    GeminiFlash = LLM(
        api_key=os.getenv('GEMINI_API_KEY'),
        model='gemini/gemini-2.0-flash',
    )
    
    while True:
        print("\n")
        print("1. GPT-4o Mini")
        print("2. Claude 3.5 Haiku")
        print("3. Gemini 2.0 Flash")
        print("\n")
        
        choice = input("[?] Choose LLM for Agents (1 - 3): ").strip()
        
        if choice == "1":
            return GPT4oMini, "openai"
        elif choice == "2":
            return ClaudeHaiku, "anthropic"
        elif choice == "3":
            return GeminiFlash, "gemini"
        else:
            print("❌ Invalid choice. Please enter 1 - 3.")

def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def get_target_files():
    target_filenames = []

    while True:
        print("\n")
        print("1] Single .js File")
        print("2] Directory (load all .js files)")
        print("\n")
        
        choice = input("[?] Enter your target type (1 - 2): ").strip()

        if choice == "1":
            jsfile = get_file_path("[?] Enter the path to the target .js file: ")
            if os.path.isfile(jsfile) and jsfile.endswith(".js"):
                target_filenames.append(jsfile)
                break
            else:
                print("❌ Invalid .js file. Please enter a valid path.")
            
        elif choice == "2": 
            dir_path = get_file_path("[?] Enter the directory path: ")
            if os.path.isdir(dir_path):
                for filename in os.listdir(dir_path):
                    if filename.endswith(".js"):
                        full_path = os.path.join(dir_path, filename)
                        target_filenames.append(full_path)
                if target_filenames:
                    break
                else:
                    print("⚠️ No .js files found in the directory.")
            else:
                print("❌ Directory not found. Please enter a valid path.")
        
        else:
            print("🚨 Invalid choice. Please select 1 or 2.")

    return target_filenames

def agents(llm):
    
    bughunter = Agent(
        role="Bug Hunter",
        goal="Analyze JavaScript code to discover vulnerabilities and sensitive information",
        backstory="You are a security expert specialized in finding hidden vulnerabilities and sensitive information in JavaScript code.",
        verbose=True,
        llm=llm,
        respect_context_window=True,
    )

    validator = Agent(
        role="Validation Agent",
        goal="Perform in-depth validation of discovered vulnerabilities and assess exploitation potential",
        backstory="You are an expert in validating the actual impact and exploitation possibilities of discovered vulnerabilities.",
        verbose=True,
        llm=llm,
        respect_context_window=True,
    )

    writer = Agent(
        role="Report Writer",
        goal="Compile discovered vulnerabilities and validation results into a professional security report",
        backstory="You are an expert in transforming technical findings into clear and actionable reports.",
        verbose=True,
        llm=llm,
        respect_context_window=True,
    )

    return [bughunter, validator, writer]

def task(agents, js_code):
    EXPECTED_OUTPUT = """
    [
        {
            "type": "[specific type]",
            "location": "line [line number]",
            "description": "[detailed description]",
            "snippet": "[code snippet]",
            "severity": "[none/low/medium/high/critical]",
            "PoC": "[proof of attack method]",
            "reproduction_steps": [
                "1. [first step]",
                "2. [second step]",
                "..."
            ]
        }
        ]"""
    
    task1 = Task( # Sensitive Information
        description=f"""
            # Sensitive Information Detection Task
            
            ## Your Mission
            Analyze the JavaScript code provided to discover and document hardcoded sensitive information.

            ## Provided JavaScript code
            {js_code}

            ## Types of Sensitive Information to Look For (focus exclusively on this list)
            1. API keys and tokens (Google, AWS, Firebase, etc. service keys)
            2. Encryption keys and secrets
            3. User authentication information (tokens, JWT, session IDs)
            4. Database credentials (usernames, passwords, connection strings)
            5. Personally identifiable information (emails, phone numbers, addresses)
            6. Internal server IP addresses and hostnames
            7. Development/staging environment access information
            8. Internal system information exposed during error outputs
            
            ## Instructions You Must Follow
            1. Report only information that actually exists in the code - do not make assumptions.
            2. For each finding, you must include:
            - Exact code line number
            - The problematic code snippet
            - Valid severity assessment (use CVSS v4.0 Ratings)
            3. Reconfirm each finding to verify it's actually sensitive information.
            4. Provide very specific Proof of Concept (PoC) and step-by-step reproduction methods.
        """,
        agent=agents[0],  # bughunter
        expected_output=EXPECTED_OUTPUT
    )

    task2 = Task( # API Endpoint
        description=f"""
        # API Endpoint Detection Task
        
        ## Your Mission
        Analyze the JavaScript code provided to discover and document all API endpoints.
        
        ## Provided JavaScript code
        {js_code}
        
        ## Types of Endpoints to Look For (focus exclusively on this list)
        1. REST API calls (GET, POST, PUT, DELETE, etc.)
        2. GraphQL endpoints
        3. WebSocket connections
        4. AJAX requests
        5. API endpoints accessible without authentication
        6. Debug endpoints hidden in commented code
        7. Admin functionality endpoints
        8. Internal API endpoints that are exposed publicly
        
        ## Instructions You Must Follow
        1. Report only endpoints that actually exist in the code - do not make assumptions.
        2. Look carefully for these JavaScript patterns:
        - fetch(), axios(), $.ajax(), XMLHttpRequest
        - WebSocket connections
        - API path strings
        - API-related code in comments
        3. For each finding, you must include:
        - Exact code line number
        - The problematic code snippet
        - Valid severity assessment (use CVSS v4.0 Ratings)
        4. Reconfirm each finding to verify it's actually an endpoint.
        5. Provide very specific Proof of Concept (PoC) and step-by-step reproduction methods.
        """,
        agent=agents[0],  # bughunter
        expected_output=EXPECTED_OUTPUT
    )

    task3 = Task( # Potential Vulnerability
        description=f"""
        # Potential Vulnerability Detection Task
        
        ## Your Mission
        Analyze the JavaScript code provided to discover and document potential security vulnerabilities.

        ## Provided JavaScript code
        {js_code}
        
        ## Types of Vulnerabilities to Look For (focus exclusively on this list)
        1. DOM-based XSS vulnerabilities (innerHTML, document.write, etc.)
        2. Input validation patterns that rely only on client-side validation
        3. Missing CSRF defenses
        4. Unsafe JSON parsing (using eval, etc.)
        5. Prototype pollution possibilities (Object.assign, object merging)
        6. postMessage handlers with insufficient origin validation
        7. Unsafe JSONP implementations
        8. DOM-based redirect vulnerabilities
        
        ## Instructions You Must Follow
        1. Report only vulnerabilities that actually exist in the code - do not make assumptions.
        2. Look carefully for these JavaScript patterns:
        - Use of innerHTML, outerHTML, document.write
        - Use of eval(), setTimeout/setInterval with strings, new Function()
        - JSON.parse combined with user input
        - Object merging/assignment (Object.assign, spread operator)
        - Location changes without validation
        3. For each finding, you must include:
        - Exact code line number
        - The problematic code snippet
        - Valid severity assessment (use CVSS v4.0 Ratings)
        4. Reconfirm each finding to verify it's actually a vulnerability.
        5. Provide very specific Proof of Concept (PoC) and step-by-step reproduction methods.
        """,
        agent=agents[0],  # bughunter
        expected_output=EXPECTED_OUTPUT
    )

    task4 = Task( # Critical Function
        description=f"""
        # Critical Function Detection Task
        
        ## Your Mission
        Analyze the JavaScript code provided to discover and document security-critical functions.

        ## Provided JavaScript code
        {js_code}

        ## Types of Critical Functions to Look For (focus exclusively on this list)
        1. Authentication functions (login, session management, token validation)
        2. Authorization functions (permission checking, access control)
        3. Payment processing functions (price calculation, payment verification)
        4. Data handling functions (query, modify, delete)
        5. Input validation and sanitization functions (document.write, eval())
        6. Encryption/decryption functions
        7. Business logic processing functions
        8. Error handling and logging functions
        9. Redirect functions (location.href, window.open)
        10. Javascript functions (javascript:)
        
        ## Instructions You Must Follow
        1. Report only functions that actually exist in the code - do not make assumptions.
        2. Verify if each function is executed only on the client-side.
        3. Pay special attention to important logic that's processed only on the client without server validation.
        4. For each finding, you must include:
        - Exact code line number
        - The problematic code snippet
        - Valid severity assessment (use CVSS v4.0 Ratings)
        5. Reconfirm each finding to verify there's an actual security risk.
        6. Provide very specific PoC and step-by-step methods for bypassing or disabling the function.
        """,
        agent=agents[0],  # bughunter
        expected_output=EXPECTED_OUTPUT
    )

    task5 = Task( # Validation Task
        description=f"""
        # Vulnerability Validation Task
        
        ## Your Mission
        Thoroughly validate all suspicious items found by the bug hunter, and report only actual vulnerabilities after filtering.
        Review the JavaScript code provided to verify the findings.

        ## Provided JavaScript code
        {js_code}

        ## Validation Steps to Perform
        For each finding, answer these 3 key questions:
        
        1. **Existence**: Does this issue actually exist in the code?
        - Verify the code line numbers and snippets are accurate
        - Confirm it can be actually observed in the provided code
        
        2. **Exploitability**: Can this issue be actually exploited?
        - Logically analyze if the provided PoC would work
        - Review if a real attack scenario is possible
        - Assess attack difficulty and any prerequisites
        
        3. **Severity Accuracy**: Is the assigned severity appropriate?
        - Evaluate based on actual security impact based on CVSS v4.0 Ratings
        - Adjust overestimated or underestimated severity
        
        ## Instructions You Must Follow
        1. Exclude all items confirmed to be false positives.
        2. Correct any findings that are partially accurate with the right information.
        3. Adjust severity ratings that are incorrectly assessed.
        4. Base your validation results on code and security expertise.
        5. Write a concise reason for each validated item in the exploitation_scenario field.
        """,
        agent=agents[1],  # validator
        expected_output="""
        [
        {
            "type": "[original type]",
            "location": "line [line number]",
            "description": "[validated description]",
            "snippet": "[code snippet]",
            "severity": "[validated severity]",
            "verified": true,
            "exploitation_scenario": "[explanation of realistic exploitation method]",
            "PoC": "[validated proof of attack method]",
            "reproduction_steps": [
                "1. [first step]",
                "2. [second step]",
                "..."
            ]
        }
        ]
        """
    )

    task6 = Task( # Report
        description="""
        # Security Report Writing Task
        
        ## Your Mission
        Create a clear and professional JavaScript security analysis report based on the validated findings.
        
        ## Required Report Components
        1. **Executive Summary**: 
        - Clearly categorize discovered issues by severity (Critical, High, Medium, Low)
        - Visually represent the total number of findings with emojis
        
        2. **Detailed Findings**:
        - Sort by severity (Critical → High → Medium → Low)
        - Provide standardized format descriptions for each vulnerability
        
        ## Instructions You Must Follow
        1. Organize findings precisely by severity.
        2. Write vulnerability descriptions that are technically accurate but understandable to non-technical stakeholders.
        3. Include exactly these fields for each vulnerability description:
        - Type
        - Location
        - Description
        - Code Snippet
        - PoC
        - Reproduction Steps
        4. Use color emojis to indicate severity (🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low).
        5. Do not include mitigation recommendations or technical appendices.
        """,
        agent=agents[2],  # writer
        expected_output="""
        # JavaScript Recon Report
        
        ## Executive Summary
        
        This security analysis examined the JavaScript code and identified:
        - 🔴 X Critical, 🟠 X High, 🟡 X Medium, 🔵 X Low severity issues
        
        ### 🔴 Critical Vulnerabilities
        
        #### [Vulnerability Title]
        - **Type**: [original type]
        - **Location**: line [line number]
        - **Description**: [detailed description]
        - **Code Snippet**:
        ```javascript
        [code snippet]
        ```
        - **PoC**:
        ```
        [proof of attack method]
        ```
        - **Reproduction Steps**:
        1. [first step]
        2. [second step]
        ...
        
        [remaining severity sections...]
        """
    )

    return [task1, task2, task3, task4, task5, task6]

if __name__ == "__main__":

    # Display banner
    clear_terminal()
    display_banner()

    # Select LLM
    llm, llm_type = select_llm()
    agents = agents(llm)  

    # API KEY verification
    load_dotenv()
    verify_api_key(llm_type)

    # Select js file(s)
    clear_terminal()
    js_filenames = get_target_files()

    # Make directory for logging
    date = datetime.now().strftime("%y%m%d")
    LOG_DIR = os.path.join("./log", date)
    os.makedirs(LOG_DIR, exist_ok=True)

    for js in js_filenames:
        with open(js, 'r', encoding='utf-8') as js_file:
            js_code = js_file.read()

        tasks = task(agents, js_code) 

        crew = Crew(
            agents=agents,
            tasks=tasks,
            verbose=1,
            max_rpm=30, 
            output_log_file=True,
        )

        print(f"Analyzing {js}...")
        
        result = crew.kickoff()
        print(f"Token Usage: {result.token_usage}")

        report = os.path.join(LOG_DIR, f"{date}_{os.path.basename(js)}.md")

        with open(report, "w", encoding="utf-8") as f:
            f.write(str(result))