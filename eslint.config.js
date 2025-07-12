import globals from "globals";
import { defineConfig } from "eslint/config";

export default defineConfig([
	  {
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node,
            },
        },
  	  	rules: {
  	  		  // Existing rules
  	  		  semi: "error",
  	  		  "prefer-const": "error",
  	  		
  	  		  // Match your existing style
  	  		  "quotes": ["error", "single"],
  	  		  "indent": ["error", 4, { "SwitchCase": 1 }],
  	  		  "no-trailing-spaces": "error",
  	  		  "no-unused-vars": ["error", { "argsIgnorePattern": "^_", "caughtErrors": "none" }],
  	  		  "no-undef": "error",
  	  	},
	  },
]);