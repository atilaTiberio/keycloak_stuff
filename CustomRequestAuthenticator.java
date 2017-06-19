package mx.horacio.filtro;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OAuthRequestAuthenticator;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AdapterSessionStore;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.HttpFacade;

import java.util.logging.Logger;

/**
 * Created by hiturbe on 14/06/17.
 */
public class CustomRequestAuthenticator extends OAuthRequestAuthenticator {

    private  String uri;



    private static final Logger log= Logger.getLogger(KeycloakFiltro.class.getName());

    public CustomRequestAuthenticator(RequestAuthenticator requestAuthenticator, HttpFacade facade, KeycloakDeployment deployment, int sslRedirectPort, AdapterSessionStore tokenStore) {
        super(requestAuthenticator, facade, deployment, sslRedirectPort, tokenStore);
        this.uri=getRedirectUri(getStateCode());
    }

   public String uriToRedirect(String params){
       StringBuffer sb= new StringBuffer(this.uri);
       sb.append(params);
       return sb.toString();
   }











}
