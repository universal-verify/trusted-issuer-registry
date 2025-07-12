import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { validateSchemaFiles } from "./schema-check.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function checkWorkingDirectory() {
    const status = execSync("git status --porcelain").toString();
    if (status) {
        console.error("❌ Working directory is not clean. Commit your changes before publishing.");
        process.exit(1);
    }
    console.log(` ✅ Working directory check passed`);
}

function checkBranch() {
    const branch = execSync("git rev-parse --abbrev-ref HEAD").toString().trim();
    if (branch !== "main") {
        console.error(`❌ You are on '${branch}' branch. Switch to 'main' before publishing.`);
        process.exit(1);
    }
    console.log(` ✅ Branch check passed`);
}

async function checkPatchVersionDeprecation() {
    const packageJsonPath = path.resolve(__dirname, "..", "package.json");
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
    const version = packageJson.version;
    const patchVersion = parseInt(version.split(".")[2]);
    
    const deprecationPath = path.resolve(__dirname, "..", "deprecation.json");
    const deprecationExists = fs.existsSync(deprecationPath);
    
    if (patchVersion === 0 && deprecationExists) {
        console.error("❌ Patch version is 0 but deprecation.json exists. Remove deprecation.json before publishing a new minor version.");
        process.exit(1);
    }
    
    // Check if patch version is not 0, deprecation.json doesn't exist, but it existed in the previous patch version
    if (patchVersion !== 0 && !deprecationExists) {
        const majorMinorVersion = version.split(".").slice(0, 2).join(".");
        const previousPatchVersion = patchVersion - 1;
        const previousVersion = `${majorMinorVersion}.${previousPatchVersion}`;
        
        try {
            // Check if deprecation.json existed in the previous published version via jsdelivr
            const jsdelivrUrl = `https://cdn.jsdelivr.net/npm/trusted-issuer-registry@${previousVersion}/deprecation.json`;
            const response = await fetch(jsdelivrUrl);
        
            if (response.ok) {
                console.error(`❌ Patch version ${patchVersion} but deprecation.json was removed. The deprecation.json file existed in published version ${previousVersion} and should not be removed in a new patch version.`);
                process.exit(1);
            }
        } catch (error) {
            console.error(`❌ Could not verify if deprecation.json existed or not in previous version ${previousVersion} (network error)`);
            process.exit(1);
        }
    }
    console.log(` ✅ Patch version deprecation check passed`);
}

function checkVersionConsistency() {
    const packageJsonPath = path.resolve(__dirname, "..", "package.json");
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
    const version = packageJson.version;
    
    const constantsPath = path.resolve(__dirname, "constants.js");
    const constantsContent = fs.readFileSync(constantsPath, "utf8");
    const minorVersionMatch = constantsContent.match(/const MINOR_VERSION = "([^"]+)"/);
    
    if (!minorVersionMatch) {
        console.error("❌ Could not find MINOR_VERSION in constants.js");
        process.exit(1);
    }
    
    const constantsMinorVersion = minorVersionMatch[1];
    const packageMinorVersion = version.split(".").slice(0, 2).join(".");
    
    if (constantsMinorVersion !== packageMinorVersion) {
        console.error(`❌ Version mismatch: constants.js has ${constantsMinorVersion} but package.json has ${packageMinorVersion}`);
        process.exit(1);
    }
    console.log(` ✅ Version consistency check passed`);
}

function checkFilesAgainstSchemas() {
    const validFiles = validateSchemaFiles();
    console.log(` ✅ Schema validation passed: ${validFiles} valid files checked.`);
}

try {
    checkWorkingDirectory();
    checkBranch();
    await checkPatchVersionDeprecation();
    checkVersionConsistency();
    checkFilesAgainstSchemas();
  
    console.log("✅ All pre-publish sanity checks passed.");
} catch (e) {
    console.error("❌ Error during pre-publish checks:", e.message);
    process.exit(1);
}