package com.example.selenium;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.support.ui.ExpectedConditions;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class LoginTest {

    private static WebDriver driver;
    private static WebDriverWait wait;
    private static final int TIMEOUT = 10;
    private static List<String> testResults;

    public static void main(String[] args) {
        System.out.println("=== Login Test Suite ===");

        testResults = new ArrayList<>();

        try {
            runTest1_ValidLogin();
            runTest2_InvalidLogin();
            runTest3_BlankFields();

            printSummary();

        } catch (Exception e) {
            System.err.println("Test Suite Failed: " + e.getMessage());
            e.printStackTrace();

        } finally {
            cleanupDriver();
        }
    }

    /* ============================================================
                       TEST CASE 1 — VALID LOGIN
       ============================================================ */
    private static void runTest1_ValidLogin() {
        System.out.println("\n[TC01] Running: Valid Login");

        try {
            initializeDriver();

            driver.get("https://practicetestautomation.com/practice-test-login/");
            wait.until(ExpectedConditions.presenceOfElementLocated(By.id("username")));

            driver.findElement(By.id("username")).clear();
            driver.findElement(By.id("username")).sendKeys("student");

            driver.findElement(By.id("password")).clear();
            driver.findElement(By.id("password")).sendKeys("Password123");

            driver.findElement(By.id("submit")).click();

            Thread.sleep(2000);

            String url = driver.getCurrentUrl();

            if (url.contains("logged-in-successfully")) {
                testResults.add("[PASS] TC01: Valid login successful");
                System.out.println("[PASS] Redirected to: " + url);
            } else {
                testResults.add("[FAIL] TC01: Expected success page. URL: " + url);
                System.out.println("[FAIL] URL: " + url);
            }

        } catch (Exception e) {
            testResults.add("[ERROR] TC01: " + e.getMessage());
            System.err.println("[ERROR] TC01: " + e.getMessage());
        }
    }

    /* ============================================================
                       TEST CASE 2 — INVALID LOGIN
       ============================================================ */
    private static void runTest2_InvalidLogin() {
        System.out.println("\n[TC02] Running: Invalid Login");

        try {
            if (driver == null) initializeDriver();

            driver.get("https://practicetestautomation.com/practice-test-login/");
            wait.until(ExpectedConditions.presenceOfElementLocated(By.id("username")));

            driver.findElement(By.id("username")).clear();
            driver.findElement(By.id("username")).sendKeys("invaliduser");

            driver.findElement(By.id("password")).clear();
            driver.findElement(By.id("password")).sendKeys("invalidpass");

            driver.findElement(By.id("submit")).click();

            Thread.sleep(2000);

            try {
                WebElement msg = wait.until(
                        ExpectedConditions.presenceOfElementLocated(
                                By.xpath("//*[contains(text(),'Your username is invalid')]")
                        )
                );

                if (msg.isDisplayed()) {
                    testResults.add("[PASS] TC02: Invalid login error shown");
                    System.out.println("[PASS] Error message shown");
                }

            } catch (Exception e) {
                testResults.add("[FAIL] TC02: Error message NOT shown");
                System.out.println("[FAIL] No invalid username message");
            }

        } catch (Exception e) {
            testResults.add("[ERROR] TC02: " + e.getMessage());
            System.err.println("[ERROR] TC02: " + e.getMessage());
        }
    }

    /* ============================================================
                       TEST CASE 3 — BLANK FIELDS
       ============================================================ */
    private static void runTest3_BlankFields() {
        System.out.println("\n[TC03] Running: Blank Fields");

        try {
            if (driver == null) initializeDriver();

            driver.get("https://practicetestautomation.com/practice-test-login/");
            wait.until(ExpectedConditions.presenceOfElementLocated(By.id("username")));

            // Clear both fields without entering anything
            driver.findElement(By.id("username")).clear();
            driver.findElement(By.id("password")).clear();

            driver.findElement(By.id("submit")).click();

            Thread.sleep(2000);

            try {
                WebElement msg = wait.until(
                        ExpectedConditions.presenceOfElementLocated(
                                By.xpath("//*[contains(text(),'Your username is invalid')]")
                        )
                );

                if (msg.isDisplayed()) {
                    testResults.add("[PASS] TC03: Validation shown for blank fields");
                    System.out.println("[PASS] Blank field validation working");
                }

            } catch (Exception e) {
                testResults.add("[FAIL] TC03: No validation for blank fields");
                System.out.println("[FAIL] No validation");
            }

        } catch (Exception e) {
            testResults.add("[ERROR] TC03: " + e.getMessage());
            System.err.println("[ERROR] TC03: " + e.getMessage());
        }
    }

    /* ============================================================
                         FIXED DRIVER INITIALIZATION
       ============================================================ */
    private static void initializeDriver() {
        try {
            System.setProperty("webdriver.edge.driver",
                    "C:\\Users\\jshah\\Downloads\\edgedriver_win32\\msedgedriver.exe");

            EdgeOptions options = new EdgeOptions();

            // ✔ Full headless mode
            options.addArguments("--headless=new");
            options.addArguments("--disable-gpu");
            options.addArguments("--no-sandbox");
            options.addArguments("--window-size=1920,1080");

            // ✔ FIXED — assign to class-level driver
            driver = new EdgeDriver(options);

            wait = new WebDriverWait(driver, Duration.ofSeconds(TIMEOUT));

            System.out.println("[INFO] WebDriver initialized (headless)");

        } catch (Exception e) {
            System.err.println("[ERROR] WebDriver initialization failed: " + e.getMessage());
            throw e;
        }
    }

    /* ============================================================
                             CLEANUP DRIVER
       ============================================================ */
    private static void cleanupDriver() {
        if (driver != null) {
            try {
                driver.quit();
                System.out.println("\n[INFO] WebDriver closed");
            } catch (Exception e) {
                System.err.println("[ERROR] Error closing WebDriver: " + e.getMessage());
            }
        }
    }

    /* ============================================================
                             PRINT SUMMARY
       ============================================================ */
    private static void printSummary() {
        System.out.println("\n==================================================");
        System.out.println("                TEST EXECUTION SUMMARY");
        System.out.println("==================================================");

        int passed = 0, failed = 0, errors = 0;

        for (String r : testResults) {
            System.out.println(r);
            if (r.contains("[PASS]")) passed++;
            else if (r.contains("[FAIL]")) failed++;
            else if (r.contains("[ERROR]")) errors++;
        }

        System.out.println("--------------------------------------------------");
        System.out.println("Total Passed: " + passed);
        System.out.println("Total Failed: " + failed);
        System.out.println("Total Errors: " + errors);
        System.out.println("Total Tests: " + testResults.size());
        System.out.println("--------------------------------------------------");

        System.out.println("\nTest Execution Completed");
    }

    /* ============================================================
                      METHOD USED BY YOUR API (if any)
       ============================================================ */
    public static String runTests() {
        StringBuilder out = new StringBuilder();
        out.append("Login Test Results:\n");

        try {
            testResults = new ArrayList<>();
            runTest1_ValidLogin();
            runTest2_InvalidLogin();
            runTest3_BlankFields();

            for (String r : testResults) out.append(r).append("\n");

        } catch (Exception e) {
            out.append("Test Failed: ").append(e.getMessage());

        } finally {
            cleanupDriver();
        }

        return out.toString();
    }
}
