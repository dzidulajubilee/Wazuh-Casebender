# Wazuh + Casebender 
This integration makes Wazuh automatically create security incident as an alert/case in Casebender every time it detects an important event.

Tested on Casebender and Wazuh 4.11.2 (Ubuntu 22.04) 

# STEP 1 

Build your casebender Box Refer to the official Documentation of Casebender
```
https://docs.casebender.com/en/quickstart
```

Generate API for Super User

![image](https://github.com/user-attachments/assets/ffa85c2d-b14e-4672-9859-882c9cd9da25)



Copy your API Key and API Secret and Store Safe



# STEP 2 

Clone this repo on your wazuh server

```
git clone https://github.com/dzidulajubilee/Wazuh-Casebender.git
```

# STEP 3  - Navigate into the cloned repo and copy the necessary files into Wazuh's Integration Directory 


```

cp custom-casebender /var/ossec/integrations/

cp custom-casebender.py /var/ossec/integrations/

nano custom-casebender.py

Replace the section HARDCODED_API_SECRET with your API secret and save the file


```

# Step 4 - Configure Permission and Ownership 

```
chmod 755 /var/ossec/integrations/custom-casebender
chmod 755 /var/ossec/integrations/custom-casebender.py

chown root:wazuh /var/ossec/integrations/custom-casebender
chown root:wazuh /var/ossec/integrations/custom-casebender.py

```

# STEP5 - Final integration step - enabling the integration in the Wazuh manager configuration file  <br>

Modify `/var/ossec/etc/ossec.conf` and insert the below code. You will need to insert the IP address and port for your Casebender server inside the `<hook_url>` tags as well as insert your API key inside the `<api_key>` tags. 

Place Below the Global Tag

```
<!-- Custom external Integration -->
   <integration>
    <name>custom-casebender</name>
    <hook_url>http://192.168.28.101:3000</hook_url> <!-- Actually your API URL -->
    <api_key>PUT YOUR API KEY HERE</api_key> <!-- Your API key -->
    <level>0</level>
    <alert_format>json</alert_format>
 </integration>
```

Once complete, you need to restart Wazuh Manager:

`sudo systemctl restart wazuh-manager`

You should see alerts being generated under the `Alerts` and `Cases` being created in the respective tab in the Casebender Instance.




# Alerts


 ![image](https://github.com/user-attachments/assets/f2e99340-74e3-4f25-aea6-7a75891a1b13)






 
