#! /bin/sh

# Builds .jar for the Globus Online Shibboleth authentication servlet. Needs 
# access to the libraries included in the Shibboleth IdP binary distributions,
# which may be gotten at http://www.shibboleth.net/downloads/identity-provider/

if [ $# -ne 2 ] 
then
	echo "Usage: ./build.sh <path to Shibboleth IdP libraries>"
	exit
fi

export CLASSPATH=$1"/*" 

mkdir bin
javac -d ./bin/ src/main/java/edu/internet2/middleware/shibboleth/idp/authn/provider/GlobusOnlineAuthServlet.java
jar cvf globus_online_auth_servlet.jar ./bin/edu/internet2/middleware/shibboleth/idp/authn/provider/GlobusOnlineAuthServlet.class
