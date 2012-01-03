This is the Shibboleth idp for globusonline.  The project is built using gradle (http://gradle.org)

Once gradle is installed, you can install this project by doing:

gradle clean servlet:buildStandaloneWar

This will compile the war and create an executable war file.  The file is written to servlet/build/globusonline-shib-idp.war

To run the server you can do:  java -jar servlet/build/globuosnline-ssh-idp.war

