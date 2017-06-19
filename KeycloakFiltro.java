package mx.horacio.filtro;

import com.sun.tools.doclets.formats.html.SourceToHTMLConverter;
import org.apache.http.HttpStatus;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.servlet.FilterRequestAuthenticator;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore;
import org.keycloak.adapters.servlet.OIDCServletHttpFacade;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Logger;

/**
 * Created by hiturbe on 02/06/17.
 */
public class KeycloakFiltro extends KeycloakOIDCFilter {
        private static boolean yaquedo;

    private static final Logger log= Logger.getLogger(KeycloakFiltro.class.getName());

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest)req;
        HttpServletResponse response = (HttpServletResponse)res;

        HttpSession httpSession = request.getSession(false);

        OIDCServletHttpFacade facade = new OIDCServletHttpFacade(request, response);
        KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
        OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(request, facade, 100000, deployment, this.idMapper);
        FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(deployment, tokenStore, facade, request, 8443);
        CustomRequestAuthenticator cra = new CustomRequestAuthenticator(authenticator, facade, deployment, 8443, tokenStore);

            if(this.skipPattern != null) {
                String requestPath = request.getRequestURI().substring(request.getContextPath().length());
                if(this.skipPattern.matcher(requestPath).matches()&&request.getQueryString()==null){

                    response.sendRedirect(cra.uriToRedirect("&username=portal&password=portal"));
                }
                else{
                    super.doFilter(req,res,chain);
                }
            }


   }



}
