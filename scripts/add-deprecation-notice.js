import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import readline from 'readline';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Function to check if deprecation_notice.json already exists
function checkExistingDeprecation() {
    const projectRoot = path.resolve(__dirname, '..');
    const deprecationPath = path.join(projectRoot, 'deprecation_notice.json');

    if (fs.existsSync(deprecationPath)) {
        console.error('Error: deprecation_notice.json already exists in the root directory.');
        console.error("It's advised against updating the deprecation date within a given minor version.");
        process.exit(1);
    }
}

// Function to validate date format
function validateDateFormat(dateString) {
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(dateString)) {
        return false;
    }

    const date = new Date(dateString + 'T00:00:00.000Z');
    return !isNaN(date.getTime()) && date.toISOString().startsWith(dateString);
}

// Function to convert date to epoch time
function dateToEpoch(dateString) {
    const date = new Date(dateString + 'T00:00:00.000Z');
    return Math.floor(date.getTime() / 1000);
}

// Function to check if date is in the past
function isDateInPast(dateString) {
    const inputDate = new Date(dateString + 'T00:00:00.000Z');
    const now = new Date();
    return inputDate < now;
}

// Function to prompt user for date
function promptForDate() {
    return new Promise((resolve) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        // Calculate 90 days from now for the example
        const ninetyDaysFromNow = new Date();
        ninetyDaysFromNow.setDate(ninetyDaysFromNow.getDate() + 90);
        const exampleDate = ninetyDaysFromNow.toISOString().split('T')[0];
        
        console.log('\nPlease enter a date in YYYY-MM-DD format (e.g., ' + exampleDate + ')');
        console.log('Note: The date will be interpreted as UTC timezone. The example above is 90 days from now.');

        rl.question('Date: ', (input) => {
            rl.close();
            resolve(input.trim());
        });
    });
}

// Main function
async function addDeprecation() {
    try {
        // Check if deprecation_notice.json already exists
        checkExistingDeprecation();

        // Prompt user for date
        const dateInput = await promptForDate();

        // Validate date format
        if (!validateDateFormat(dateInput)) {
            console.error('Error: Invalid date format. Please use YYYY-MM-DD format (e.g., 2024-12-31)');
            process.exit(1);
        }

        // Check if date is in the past
        if (isDateInPast(dateInput)) {
            console.error('Error: The provided date is in the past. Deprecation dates must be in the future.');
            process.exit(1);
        }

        // Convert to epoch time
        const epochTime = dateToEpoch(dateInput);

        // Create deprecation object
        const deprecation = {
            end_of_life: epochTime
        };

        // Write to file
        const projectRoot = path.resolve(__dirname, '..');
        const deprecationPath = path.join(projectRoot, 'deprecation_notice.json');

        fs.writeFileSync(deprecationPath, JSON.stringify(deprecation, null, 2) + '\n');

        console.log('\n✓ Deprecation file created successfully!');
        console.log(`File: ${deprecationPath}`);
        console.log(`Date: ${dateInput} (UTC)`);
        console.log(`Epoch time: ${epochTime}`);

    } catch (error) {
        console.error('Error during deprecation process:', error.message);
        process.exit(1);
    }
}

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    addDeprecation();
}

export { addDeprecation };