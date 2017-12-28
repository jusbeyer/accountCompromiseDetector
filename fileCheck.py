import re, ldap, ConfigParser

# Build Config Parser for script
config = ConfigParser.SafeConfigParser()

# Set all Defaults to Blank or False
fromFile = False

# Password Policy
minLength = 0
complexityRequirement = False

# File Details
input_file_path = ""
# Separator between username and password
separator = ''
output_file_path = ""

# Verify Name and use LDAP to check account
checkName = False
checkLdap = False
ldapServer = ""
# The username and password can be left blank for unpriviliged access to the ldap server
ldapUsername = ""
ldapPassword = ''
baseDN = ''


def build_config():

    try:
        with open('config.ini', 'w') as cfgFile:
            config.add_section('LDAP')
            config.set('LDAP', 'Server', raw_input("Enter the LDAP Server URL: "))
            config.set('LDAP', 'BaseDN', raw_input("Enter the LDAP Server Base DN: "))
            config.set('LDAP', 'BindUsername', raw_input("Enter the LDAP Server Bind Account Username: "))
            config.set('LDAP', 'BindPassword', raw_input("Enter the LDAP Server Bind Account Password: "))
            config.add_section('Password-Policy')
            config.set('Password-Policy', 'Min-Length', raw_input("Enter the Minimum Password Length for the Domain: "))
            config.set('Password-Policy', 'Complexity-Req',
                       raw_input("Do you have a password complexity requirement? "))
            config.add_section('Script-Config')
            config.set('Script-Config', 'ReadFile',
                       raw_input("Would you like to read usernames and passwords from a file? "
                                 "(More information will be requested later) "))
            config.set('Script-Config', 'CheckNames',
                       raw_input("Would you like to check for names in passwords? "
                                 "(This is part of most password complexity requirements and requires LDAP Access) "))
            config.set('Script-Config', 'CheckLdap',
                       raw_input("Would you like to verify if usernames and passwords given are correct? "))

            if config.getboolean("Script-Config", "ReadFile"):
                config.add_section("File-Details")
                config.set('File-Details', 'InputFile',
                           raw_input("Please provide the full path to the input file: "))
                config.set('File-Details', 'Separator',
                           raw_input("Please provide the separation character between usernames and passwords: "))
                config.set('File-Details', 'OutputFile',
                           raw_input("Please provide the path to where we should store your output file: "))
            config.write(cfgFile)
            cfgFile.close()
            return True
    except IOError:
        print "Could not write config file"
        return False


# Method to set all global variables based on the config.ini file
def check_config():
    try:
        with open('config.ini', 'r') as f:
            config.readfp(f)
            # Bring In Globals
            # Read from file or prompt
            global fromFile
            # Password Policy
            global minLength
            global complexityRequirement

            # File Details
            global input_file_path
            # Separator between username and password
            global separator
            global output_file_path

            # Verify Name and use LDAP to check account
            global checkName
            global checkLdap
            global ldapServer
            # The username and password can be left blank for unpriviliged access to the ldap server
            global ldapUsername
            global ldapPassword
            global baseDN

            # Start using ConfigParser
            # File stuff may or may not run based on boolean
            fromFile = config.getboolean("Script-Config", "ReadFile")
            if fromFile:
                input_file_path = config.get("File-Details", "InputFile")
                output_file_path = config.get("File-Details", "OutputFile")
                separator = config.get("File-Details", "Separator")

            # LDAP Config
            ldapServer = config.get("LDAP", "Server")
            ldapServer = "ldap://" + str(ldapServer)
            baseDN = config.get("LDAP", "BaseDN")
            ldapUsername = config.get("LDAP", "BindUsername")
            ldapPassword = config.get("LDAP", "BindPassword")

            # Password Policy
            minLength = config.getint("Password-Policy", "Min-Length")
            complexityRequirement = config.getboolean("Password-Policy", "Complexity-Req")

            # How deep do we go
            checkName = config.get("Script-Config", "CheckNames")
            checkLdap = config.get("Script-Config", "CheckLdap")
        f.close()
        return True
    except IOError:
        'No config.ini exists. Please enter the following information'
        if build_config():
            check_config()
        else:
            return False


def check_user(username, password):
    # type: (str, str) -> bool
    try:
        l = ldap.initialize(ldapServer)
        l.bind_s(username, password)
        l.unbind_s()
        return True
    except ldap.INVALID_CREDENTIALS:
        return False
    except ldap.LDAPError, e:
        print e
        exit(-1)


def check_password(username, password):
    # type: (str, str) -> bool
    if len(password) > minLength:
        if complexityRequirement:
            complexity = 0
            if re.search("[a-z]", password):
                complexity += 1
            if re.search("[A-Z]", password):
                complexity += 1
            if re.search("[0-9]", password):
                complexity += 1
            if re.search(("[\~\!\@\#\$\%\^\&\*\_\-\+\=\`\|\\(\)\{\}\[\]\:\;\"\'\<\>\,\.\?\/]"), password):
                complexity += 1
            if complexity >= 3 and checkName:
                try:
                    l = ldap.initialize(ldapServer)
                    l.bind_s(ldapUsername, ldapPassword)
                except ldap.LDAPError, e:
                    print e
                    l.unbind_s()
                    exit(-1)
                search_scope = ldap.SCOPE_SUBTREE
                search_filter = 'userPrincipalName=' + str(username)
                retrieve_attributes = ['samAccountName', 'displayName']
                try:
                    result_data = l.search_s(baseDN, search_scope, search_filter, retrieve_attributes)
                    l.unbind_s()
                    if len(result_data) > 0:
                        result_data = result_data[0][1]

                    if not result_data:
                        return False

                    # check for samAccountName in password
                    if len(result_data["sAMAccountName"][0]) > 3:
                        sam_pat = re.compile(result_data["sAMAccountName"][0], re.IGNORECASE)
                        if re.search(sam_pat, password):
                            return False

                    # check for any part of displayName in password
                    display_name_tokens = re.split("[\,\_\\s\-\#]", result_data["displayName"][0])
                    for token in display_name_tokens:
                        if len(token) < 3:
                            continue
                        else:
                            display_pat = re.compile(token, re.IGNORECASE)
                            if re.search(display_pat, password):
                                return False

                    return True
                except ldap.LDAPError, e:
                    print e
                    exit(-1)
            elif complexity >= 3 and not checkName:
                return True
            else:
                return False
        else:
            return True
    else:
        return False


def main():
    if check_config():
        valid_users = []
        compromised_users = []
        # Reads in data from file
        if fromFile:
            with open(input_file_path) as f:
                for line in f:
                    line_data = line.split(separator)

                    if len(line_data) == 2:
                        username = line_data[0]
                        password = line_data[1]
                        if check_password(username, password):
                            valid_users.append(line_data)
        else:
            # Does console prompting
            while True:
                username = raw_input("Enter the username or type exit when finished: ")
                if username.lower() == 'exit':
                    print "Testing users now."
                    break
                password = raw_input("Enter the password: ")
                if check_password(username, password):
                    valid_users.append([username, password])

        if checkLdap and valid_users != []:
            for user in valid_users:
                if check_user(user[0], user[1]):
                    compromised_users.append(user[0])
        if len(compromised_users) > 0:
            if fromFile:
                with open(output_file_path + "compromised_users.csv", 'w') as outFile:
                    for user in compromised_users:
                        outFile.write("%s\n" % user)
                    outFile.close()
            else:
                print "Compromised Users: " + str(compromised_users)
    else:
        exit()


if __name__ == '__main__':
    main()
