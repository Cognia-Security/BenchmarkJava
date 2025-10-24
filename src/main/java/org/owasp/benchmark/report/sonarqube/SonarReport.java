package org.owasp.benchmark.report.sonarqube;

import static java.lang.String.join;
import static java.nio.charset.Charset.defaultCharset;
import static org.apache.commons.io.FileUtils.writeStringToFile;
import static org.apache.commons.io.IOUtils.readLines;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmark.report.sonarqube.dto.SonarQubeResult;

public class SonarReport {
    private static final String SONAR_BASE_URL = "https://sonarcloud.io";
    private static final String SONAR_ORGANIZATION =
            envOrDefault("SONAR_ORGANIZATION", "Cognia-Security");
    private static final String SONAR_PROJECT =
            envOrDefault("SONAR_PROJECT_KEY", "Cognia-Security_BenchmarkJava");
    private static final String SONAR_BRANCH = System.getenv("SONAR_BRANCH");
    private static final String SONAR_DIRECTORIES = System.getenv("SONAR_DIRECTORIES");
    private static final String SONAR_TOKEN = requireEnv("SONAR_TOKEN");
    private static final int PAGE_SIZE = 500;

    private static final String sonarAuth =
            Base64.getEncoder()
                    .encodeToString((SONAR_TOKEN + ":").getBytes(StandardCharsets.UTF_8));

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        List<String> issues = new ArrayList<>();
        List<String> hotspots = new ArrayList<>();

        forAllPagesAt(
                "issues/search?organization="
                        + urlEncode(SONAR_ORGANIZATION)
                        + "&types=VULNERABILITY&projects="
                        + urlEncode(SONAR_PROJECT)
                        + "&languages=java"
                        + optionalQueryParameter("branch", SONAR_BRANCH)
                        + optionalQueryParameter("directories", SONAR_DIRECTORIES),
                (result -> issues.addAll(result.issues)));
        forAllPagesAt(
                "hotspots/search?organization="
                        + urlEncode(SONAR_ORGANIZATION)
                        + "&projectKey="
                        + urlEncode(SONAR_PROJECT)
                        + optionalQueryParameter("branch", SONAR_BRANCH),
                (result -> hotspots.addAll(result.hotspots)));

        writeStringToFile(
                new File("results/" + resultFilename() + ".json"),
                formattedJson(issues, hotspots),
                defaultCharset());
    }

    private static String resultFilename() throws Exception {
        return "Benchmark_" + benchmarkVersion() + "-sonarqube-v" + apiCall("server/version");
    }

    private static String benchmarkVersion() throws Exception {
        return DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(new File("pom.xml"))
                .getElementsByTagName("version")
                .item(0)
                .getTextContent();
    }

    private static void forAllPagesAt(String apiPath, Consumer<SonarQubeResult> pageHandlerCallback)
            throws IOException {
        int pages;
        int page = 1;

        do {
            String response = apiCall(apiPath + pagingSuffix(page, apiPath));
            SonarQubeResult result = objectMapper.readValue(response, SonarQubeResult.class);

            int totalResults = resultTotal(result, response, apiPath, page);
            int pageSize = resultPageSize(result, response, apiPath, page);
            pages = Math.max(1, (int) Math.ceil(totalResults / (double) pageSize));

            pageHandlerCallback.accept(result);

            page++;
        } while (page <= pages);
    }

    private static String pagingSuffix(int page, String apiPath) {
        return (apiPath.contains("?") ? "&" : "?") + "p=" + page + "&ps=" + PAGE_SIZE;
    }

    private static String apiCall(String apiPath) throws IOException {
        URL url = new URL(SONAR_BASE_URL + "/api/" + apiPath);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Authorization", "Basic " + sonarAuth);

        int status = connection.getResponseCode();
        InputStream stream =
                status >= 200 && status < 300
                        ? connection.getInputStream()
                        : connection.getErrorStream();

        if (stream == null) {
            throw new IOException("No response body from SonarCloud (" + status + ").");
        }

        String response = join("\n", readLines(stream, defaultCharset()));

        if (status < 200 || status >= 300) {
            throw new IOException(
                    "SonarCloud API call failed ("
                            + status
                            + "): "
                            + connection.getURL()
                            + "\n"
                            + response);
        }

        return response;
    }

    private static String formattedJson(List<String> issues, List<String> hotspots)
            throws JsonProcessingException {
        String sb =
                "{\"issues\":["
                        + join(",", issues)
                        + "],\"hotspots\":["
                        + join(",", hotspots)
                        + "]}";

        return objectMapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(objectMapper.readValue(sb, Object.class));
    }

    private static String optionalQueryParameter(String name, String value) {
        return isBlank(value) ? "" : "&" + name + "=" + urlEncode(value);
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to URL-encode value: " + value, ex);
        }
    }

    private static String truncate(String value) {
        int maxLength = 500;
        return value.length() <= maxLength ? value : value.substring(0, maxLength) + "...";
    }

    private static String envOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return isBlank(value) ? defaultValue : value;
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (isBlank(value)) {
            throw new IllegalStateException("Environment variable " + name + " must be set.");
        }
        return value;
    }

    private static int resultTotal(
            SonarQubeResult result, String response, String apiPath, int page) {
        if (result.paging != null) {
            return result.paging.resultCount;
        }
        if (result.totalResults != null) {
            return result.totalResults;
        }
        throw new IllegalStateException(
                "SonarCloud response missing total result count for "
                        + apiPath
                        + " (page "
                        + page
                        + "): "
                        + truncate(response));
    }

    private static int resultPageSize(
            SonarQubeResult result, String response, String apiPath, int page) {
        if (result.pageSize != null && result.pageSize > 0) {
            return result.pageSize;
        }
        if (result.paging != null && result.paging.pageSize > 0) {
            return result.paging.pageSize;
        }
        throw new IllegalStateException(
                "SonarCloud response missing page size for "
                        + apiPath
                        + " (page "
                        + page
                        + "): "
                        + truncate(response));
    }
}
