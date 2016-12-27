package certificado.poc.com.br.android_poc_registrar_certificados_ca;

import android.content.res.Resources;
import android.util.Log;
import android.webkit.URLUtil;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Created by Rudson Kiyoshi Souza Carvalho on 27/12/16.
 */
public class AppHttpConnection {

    private final static String TAG_LOG = "[AppHttpConnection]";

    //contexto SSL utilizado para realizar as chamadas http
    private static SSLContext sslContext = null;

    private static final String X_509 = "X.509";
    private static final String PROTOCOL_TLS = "TLS";
    private static final String CERT_ENTRY = "ca";


    /**
     * Inicializa o contexto SSL
     * @param endPointUrl
     * @throws ExceptionInInitializerError
     */
    private void initSSLContext(final String endPointUrl) throws  ExceptionInInitializerError {

            if (endPointUrl != null) {

                throw new ExceptionInInitializerError("Erro nao foi inicializado uma url de servico valida.");
            }

            if (URLUtil.isNetworkUrl(endPointUrl)) {
                throw new ExceptionInInitializerError("Nao eh uma url valida ".concat(endPointUrl));
            }

            try {

                openSSLContext(endPointUrl, null);

            } catch (Exception e) {

                Log.e(TAG_LOG, "Falha na inicialização SSL " + e.getMessage(), e);

                Log.i(TAG_LOG, "Tenta registrar o certificado conhecido");

                try {

                    CertificateFactory cf = CertificateFactory.getInstance(X_509);

                    //carrega o certificado armazenado na pasta raw de resources
                    InputStream caInput = new BufferedInputStream(Resources.getSystem().openRawResource(R.raw.DigiCert));

                    if (caInput != null) {

                        Certificate ca = null;

                        try {
                            ca = cf.generateCertificate(caInput);
                        } catch (Exception ex){
                            Log.e(TAG_LOG, "Error generateCertificate " + ex.getMessage(), ex);
                        } finally {
                            caInput.close();
                        }

                        // gera a keystore para o certificado confiavel
                        final String keyStoreType = KeyStore.getDefaultType();
                        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                        keyStore.load(null, null);
                        keyStore.setCertificateEntry(CERT_ENTRY, ca);

                        // cria uma trustmanager para o CA na keystore gerada
                        final String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
                        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
                        tmf.init(keyStore);

                        openSSLContext(endPointUrl, tmf.getTrustManagers());

                    } else {

                        Log.e(TAG_LOG, "Falha na inicialização SSL, nao foi identificado um certificado cadastrado.");
                    }

                } catch (Exception ex) {

                    Log.e(TAG_LOG, "Falha na inicialização SSL " + ex.getMessage(), ex);

                }
            }


        }

        /**
         * Tenta realizar uma conexao para inicializar o contexto de seguranca
         * @param endPointUrl
         * @param trustManager
         * @throws IOException
         * @throws NoSuchAlgorithmException
         * @throws KeyManagementException
         */
        private void openSSLContext(final String endPointUrl, TrustManager[] trustManager) throws IOException, NoSuchAlgorithmException, KeyManagementException {

            if (URLUtil.isHttpsUrl(endPointUrl)) {

                URL url = new URL(endPointUrl);
                URLConnection urlConnection = url.openConnection();

                if (!(urlConnection instanceof HttpsURLConnection)) {

                    //SSL TLS CONTEXT - secure socket protocol implementation
                    sslContext = SSLContext.getInstance(PROTOCOL_TLS);
                    sslContext.init(null, trustManager, null);

                    ((HttpsURLConnection) urlConnection).setSSLSocketFactory(sslContext.getSocketFactory());

                    //tenta conectar
                    urlConnection.connect();

                    // CAs instalados ok
                    ((HttpsURLConnection) urlConnection).disconnect();

                    url = null;
                    urlConnection = null;
                }
            }
        }


        /**
         * Metodo de exemplo para realizar uma chamada qualquer
         * */
        public void postExecute(final String url) throws IOException {

            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(url).openConnection();

            //Se tiver um contexto SSL
            if (sslContext != null) {
                HttpsURLConnection httpsURLConnection = ((HttpsURLConnection) httpURLConnection);
                httpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory());
            }

            httpURLConnection.setRequestProperty("Content-Type", "application/json");
            httpURLConnection.addRequestProperty("accept", "application/json");
            httpURLConnection.setRequestMethod("POST");

            httpURLConnection.getResponseCode();


        }
    }

