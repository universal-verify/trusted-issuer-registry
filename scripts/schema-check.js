import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Function to recursively find all JSON files in a directory
function findJsonFiles(dir) {
    const files = [];

    function traverse(currentDir) {
        const items = fs.readdirSync(currentDir);

        for (const item of items) {
            const fullPath = path.join(currentDir, item);
            const stat = fs.statSync(fullPath);

            if (stat.isDirectory()) {
                traverse(fullPath);
            } else if (item.endsWith('.json')) {
                files.push(fullPath);
            }
        }
    }

    traverse(dir);
    return files;
}

// Main schema validation function
function validateSchemaFiles() {
    const projectRoot = path.resolve(__dirname, '..');
    const schemaPath = path.join(projectRoot, 'trusted-issuer.schema.json');

    // Check if schema exists
    if (!fs.existsSync(schemaPath)) {
        console.error('❌ Schema file not found: trusted-issuer.schema.json');
        process.exit(1);
    }

    // Load schema
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

    // Initialize Ajv validator
    const ajv = new Ajv({ allErrors: true, verbose: true });
    addFormats(ajv);

    // Compile the validator once
    const validate = ajv.compile(schema);

    // Define directories to check
    const directories = [
        path.join(projectRoot, 'issuers'),
        path.join(projectRoot, 'test', 'issuers')
    ];

    let validFiles = 0;
    let invalidFiles = 0;

    // Process each directory
    for (const dir of directories) {
        if (fs.existsSync(dir)) {
            const jsonFiles = findJsonFiles(dir);

            for (const file of jsonFiles) {
                try {
                    const fileContent = fs.readFileSync(file, 'utf8');
                    const issuer = JSON.parse(fileContent);

                    const isValid = validate(issuer);

                    if (isValid) {
                        validFiles++;
                    } else {
                        console.error(`❌ Invalid: ${path.relative(projectRoot, file)}`);
                        console.error('   Errors:');
                        validate.errors.forEach(error => {
                            const field = error.instancePath || error.schemaPath;
                            console.error(`     ${field}: ${error.message}`);
                        });
                        invalidFiles++;
                    }

                } catch (error) {
                    console.error(`❌ Error reading ${path.relative(projectRoot, file)}: ${error.message}`);
                    invalidFiles++;
                }
            }
        } else {
            console.error(`❌ Directory not found: ${dir}`);
            process.exit(1);
        }
    }

    if (invalidFiles > 0) {
        console.error(`\n❌ Schema validation failed: ${invalidFiles} invalid files found.`);
        process.exit(1);
    }

    return validFiles;
}

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    const validFiles = validateSchemaFiles();
    console.log(`✅ Schema validation passed: ${validFiles} valid files checked.`);
}

export { validateSchemaFiles };