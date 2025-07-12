# Contributions
## Introduction

It is assumed that you already know a little about Node.js and Git. If not, [here's some help to get started with Git](https://help.github.com/en/github/using-git) and [here’s some help to get started with Node.js.](https://nodejs.org/en/docs/guides/getting-started-guide/)

* Install [Node.js](https://nodejs.org/)
* Install [Git](https://git-scm.com/)
* [Fork](https://help.github.com/en/github/getting-started-with-github/fork-a-repo) trusted-issuer-registry
* Open your OS’s terminal
* Change into the directory you’d like
* Clone your forked repo

      git clone https://github.com/[yourgithubname]/trusted-issuer-registry.git

* Go into the trusted-issuer-registry directory.

      cd ./trusted-issuer-registry

* Install the dependencies

      npm install

## Making changes

When you’ve decided to make changes, start with the following:

* Update your local repo

      git pull https://github.com/universal-verify/trusted-issuer-registry.git
      git push

* Make a new branch from the dev branch

      git checkout dev
      git branch [mychangesbranch]
      git checkout [mychangesbranch]

* Add your changes to a commit
* If you update any js files, run the linter and local test suite

      npm run lint
      npm test

* If you have updated any json files, validate them

      npm run validate-json

* Push the changes to your forked repo.
* Open a Pull Request (PR)

## Important notes:

* Don't include any build files in your commit
* Pull requests should be with respect to some GitHub issue. Please mention it with a hash (e.g. #2774), If there are no issues for your pull request, please create one first and verify it with the repo owner before needlessly doing work, there's a chance a discussion will be had and a different approach might be taken
* Pull requests should be made to the dev branch unless otherwise decided upon
* If you modify existing code or add new code, please modify or add tests when relevant
