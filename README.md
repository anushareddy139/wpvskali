
# Wordpress VS Kali

Exploits :


### 1. Comment Cross-Site Scripting
  - [ ] Summary: 
    - Vulnerability type(s): XSS (2017 OWASP Top 10: A7)
    - Version(s) affected: Wordpress 3.9 - 5.1
    - Tested in version: 4.2
    - Fixed in version: 4.2.23
  - [ ] GIF Walkthrough: 
  ![Comment XSS gif](https://github.com/anushareddy139/Assignment/blob/main/css.gif)
  - [ ] Steps to recreate:
    - Write a comment on any post
    - Include scripted elements into the comment
      - Example: <script> alert('SCRIPT ALERT') <script>
    - Post the comment for the scripted elements to be stored and applied
  - [ ] Affected source code:
    - [Link](https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b)
  
  
### 2. (Required) User Account Enumaration
  - [ ] Summary: 
    - Vulnerability types: Enumarating Users
    - Tested in version: 4.2.2
    - Fixed in version: Not fixed
  - [ ] GIF Walkthrough: [![Image from Gyazo](https://github.com/anushareddy139/Assignment/blob/main/ezgif.com-gif-maker.gif)](https://github.com/anushareddy139/Assignment/blob/main/ezgif.com-gif-maker.gif)
  - [ ] Steps to recreate: 
    - Simply log in with different usernames to see whether the user exists. Unfortunately this is also possible through permalinks:
    ```
    http://example.com/author/[insertusernamehere]
    ```
  - [ ] Affected source code:
    - [Link 1](https://core.trac.wordpress.org/browser/tags/version/src/source_file.php)
    

### 3. Sessions Not Terminated Upon Explicit User Logout
  - [ ] Summary: 
    - Vulnerability type(s): Auth Bypass/Broken Authentication (2017 OWASP Top 10: A2)
    - Version(s) affected: Wordpress 3.4.2 - 3.9.2
    - Tested in version: 3.9.1
    - Fixed in version: 4.0
  - [ ] GIF Walkthrough: 
  ![Auth Bypss gif](https://github.com/anushareddy139/Assignment/blob/main/Sessions%20Not%20Terminated%20Upon%20Explicit%20User%20Logout.gif)
  - [ ] Steps to recreate: 
    - After Admin user is logged out, use burp to grab cookie credentials
    - Apply stolen cookies to visit the admin interface 
      - Example: root/wp-admin/profile.php
  - [ ] Affected source code:
    - [Link 1](https://whiteoaksecurity.com/blog/2012/12/17/cve-2012-5868-wordpress-342-sessions-not-terminated-upon-explicit-user-logout)
    - [Link 2](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/leveraging-lfi-to-get-full-compromise-on-wordpress-sites/)
