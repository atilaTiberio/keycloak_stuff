package mx.horacio.filtro;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.util.JsonSerialization;

import java.io.InputStream;
import java.net.URI;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by hiturbe on 09/06/17.
 */
public class Ejecutable {

    public static void main(String[] args) throws Exception {
        KeycloakDeployment deployment = KeycloakDeploymentBuilder.build(Ejecutable.class.getClassLoader().getResourceAsStream("keycloak.json"));

        JWTClaimsSet claims=new JWTClaimsSet
                .Builder()
                .subject("validate")
                .claim("username","portal")
                .claim("password","portal")
                .build();

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);

        EncryptedJWT jwt = new EncryptedJWT(header, claims);

        HttpClient client =deployment.getClient();
        HttpGet get= new HttpGet(new URI(deployment.getJwksUrl()));

        HttpResponse response= client.execute(get);


        int status = response.getStatusLine().getStatusCode();

        HttpEntity entity = response.getEntity();
        if(status == 200) {

            InputStream is = entity.getContent();

            Map<String,ArrayList<HashMap<String,String>>> m=JsonSerialization.readValue(is, Map.class);
            List<HashMap<String,String>> s=m.get("keys");

            String pb=s.get(0).get("kid");
            System.out.println(pb);

            PublicKey pk=deployment.getPublicKeyLocator().getPublicKey(s.get(0).get("kid"),deployment);
            System.out.println(pk.getEncoded());

            RSAEncrypter encrypter= new RSAEncrypter((RSAPublicKey) pk);
            jwt.encrypt(encrypter);
            System.out.println(jwt.serialize());

        }

    }


}
