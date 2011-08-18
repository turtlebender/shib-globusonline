package edu.internet2.middleware.shibboleth.idp.authn.provider;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

public class GlobusOnlineAuthServlet extends HttpServlet {

    /** Serial version UID. */
    private static final long serialVersionUID = -572799841125956990L;

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(GlobusOnlineAuthServlet.class);

    /** URL to login page capable of returning the user to a callback page upon successful validation. 
     * Must end with the key of the callback parameter. */
    // TODO: Is this the login page we will be using for this?
    private static final String LOGIN_PAGE = "https://www.globusonline.org/SignIn?callback=";

    private static final String HMAC_SHA512_ALGORITHM = "HmacSHA512";
    
    private static final String SIGNATURE_SEPARATOR_REGEX = "\\|sig=";
    
    private static final String FIELD_SEPARATOR = "|";
    
    private static final String USERNAME_KEY = "un";
    
    /** Names of the query parameters used to reconstruct the signed login cookie. */
    private static String[] fieldNames = {"un", "ul", "expiry", "uid", "SigningSubject", "sig"};
    
    String sharedSecret;
    
    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        log.debug("Initializing GlobusOnlineAuthServlet");
        super.init(config);
        sharedSecret = "x3Ca9BV64E1qs5eD4zSV3gK4KAjoiTCXM0S4j1FFkGqgg81i5G"; // TODO: get this where?
    }

    /** {@inheritDoc} */
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {
        log.debug("service in GlobusOnlineAuthServlet");
        
        HttpSession session = request.getSession(true);
        
        /* Get the login context cookie. */
        Cookie loginContextCookie = HttpServletHelper.getCookie(request, AuthenticationEngine.LOGIN_CONTEXT_KEY_NAME);
        if (loginContextCookie != null) {   
            log.debug("Login context cookie: " + loginContextCookie.getValue());
        } else {
            log.debug("Login context cookie not found; returning to AuthenticationEngine.");
            /* Return and let Shibboleth produce an error message. */
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
            return;
        }

        String message = buildMessage(request);
        if (message == null) {
            /* The request contained no callback parameters, so store the request and response for later
             * user and redirect the user to the login page. */
            log.debug("Storing session data for callback.");
            session.setAttribute("request", request);
            session.setAttribute("response", response);

            log.debug("Redirecting to GlobusOnline");
            response.sendRedirect(LOGIN_PAGE + request.getRequestURL().toString());
            return;    
        } else {
            /* The message contains query parameters that could be reconstructed into a signed login cookie, 
             * so this is the callback. Attempt to validate signature and authenticate user. */
            if (validateSignature(sharedSecret, message)) {
                String username = request.getParameter(USERNAME_KEY);
                log.debug("Logging in user " + username + " using old request/response");
                request = (HttpServletRequest) session.getAttribute("request");
                response = (HttpServletResponse) session.getAttribute("response");
                request.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, username);    
            }
            /* If the signature is valid this will authenticate the user to the SP.
             * If not, Shibboleth will produce an error. */
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
            return;
        }
    }

    /**
     * Reconstruct signed login cookie from request query parameters.
     * 
     * @param request 
     * @return A string on the same format as the signed login cookie produced by Graph 
     * if the request contains all necessary parameters, null otherwise.
     */
    private String buildMessage(HttpServletRequest request) {
        StringBuilder messageBuilder = new StringBuilder();
        String field;
        log.debug("Reconstructing signed login cookie from request query parameters.");
        
        for (int i = 0; i < fieldNames.length; i++) {
         
            field = (String) request.getParameter(fieldNames[i]);
            if (field != null) {
                messageBuilder.append(fieldNames[i]);
                messageBuilder.append("=");
                messageBuilder.append(field);
                if (i < fieldNames.length - 1) {
                    messageBuilder.append(FIELD_SEPARATOR);
                }
            } else {
                log.debug("Missing parameter " + fieldNames[i] + " in request.");
                return null;
            }
        }
        String message = messageBuilder.toString();
        log.debug("Constructed message: " + message);
        return message;
    }

    private boolean validateSignature(String sharedSecret, String message) {

        String[] splitMessage = message.split(SIGNATURE_SEPARATOR_REGEX);
        for (int i = 0; i < splitMessage.length; i++) {
            System.out.println(splitMessage[i]);
            System.out.println();
        }

        if (splitMessage.length != 2) {
            log.debug("Could not validate signature; message malformed.");
            return false;
        }
        String stringToSign = splitMessage[0];
        String receivedSignature = splitMessage[1];

        boolean sigsEqual = false;
        try {
            String computedSignature = HMAC_SHA512HexSignature(stringToSign, sharedSecret);
            sigsEqual = computedSignature.equalsIgnoreCase(receivedSignature);
            if (!sigsEqual) {
                log.debug("Signature validation failed. Expected: " + receivedSignature + ", got: "
                        + computedSignature);
            }            
        } catch (Exception e) {
            log.debug("Error validating signature: " + e.getMessage());
        }
        return sigsEqual;
    }

    /**
     * Sign stringToSign with key using HMAC-SHA512. 
     * 
     * @param stringToSign
     * @param key
     * @return The signature.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalStateException
     * @throws UnsupportedEncodingException
     */
    private static String HMAC_SHA512HexSignature(String stringToSign, String key)
        throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
        Mac mac = Mac.getInstance(HMAC_SHA512_ALGORITHM);
        SecretKeySpec secret = new SecretKeySpec(key.getBytes(), mac.getAlgorithm());
        mac.init(secret);
        byte[] byteDigest = mac.doFinal(stringToSign.getBytes());       
        StringBuilder hexDigest = new StringBuilder();
        String hexByte;
        for (int i = 0; i < byteDigest.length; i++) {
            hexByte = Integer.toHexString(0xff & byteDigest[i]);
            if (hexByte.length() == 1) {
                hexDigest.append("0");
            }
            hexDigest.append(hexByte);
        }
        return hexDigest.toString();
    }
}