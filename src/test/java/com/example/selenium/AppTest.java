package com.example.selenium;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;

public class AppTest {
    public static void main(String[] args) {
        // Automatically setup ChromeDriver
        WebDriverManager.chromedriver().setup();

        ChromeOptions options = new ChromeOptions();
        // Optional headless mode (no browser UI)
        // options.addArguments("--headless=new");

        WebDriver driver = new ChromeDriver(options);

        try {
            String baseUrl = "https://example.com/login"; // 🔁 change this to your app
            driver.get(baseUrl);
            driver.manage().window().maximize();

            // ✅ Test Case 1: Valid Login
            WebElement username = driver.findElement(By.id("username"));
            WebElement password = driver.findElement(By.id("password"));
            WebElement loginBtn = driver.findElement(By.id("loginBtn"));

            username.sendKeys("admin");
            password.sendKeys("admin123");
            loginBtn.click();

            Thread.sleep(2000); // Wait for page to load

            String expectedTitle = "Dashboard - MyApp"; // change this
            if (driver.getTitle().equals(expectedTitle)) {
                System.out.println("✅ Valid Login Test Passed!");
            } else {
                System.out.println("❌ Valid Login Test Failed: Got " + driver.getTitle());
            }

            // ✅ Test Case 2: Invalid Login
            driver.get(baseUrl);
            username = driver.findElement(By.id("username"));
            password = driver.findElement(By.id("password"));
            loginBtn = driver.findElement(By.id("loginBtn"));

            username.sendKeys("wronguser");
            password.sendKeys("wrongpass");
            loginBtn.click();

            Thread.sleep(2000);

            WebElement errorMsg = driver.findElement(By.id("errorMsg"));
            if (errorMsg.isDisplayed()) {
                System.out.println("✅ Invalid Login Test Passed (Error message shown)");
            } else {
                System.out.println("❌ Invalid Login Test Failed (No error shown)");
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            driver.quit();
        }
    }
}
