const path = require("path");
const fs = require("fs");
const { promisify } = require("util");
const exec = promisify(require("child_process").exec);

const directoryPath = path.join(__dirname, "input");
const outputPath = path.join(__dirname, "output");
const config = require("./config.json");

const files = fs.readdirSync(directoryPath);
const data = [
  [
    "Repo",
    "Dependency",
    "Version",
    "Dev",
    "Package",
    "Severity",
    "Comment",
    "Info",
  ],
];

const arrayIsAtEnd = (arr, i) => {
  return arr.length - 1 === i ? true : false;
};

Promise.all(
  files.map(async (file) => {
    const rawFileContents = fs.readFileSync(path.join(directoryPath, file));

    const { name, devDependencies, dependencies } = JSON.parse(rawFileContents);

    const cmd = `cd ${config.ServicesDir}${name} && npm audit -json`;

    const getNpmAudit = async () => {
      try {
        const output = await exec(cmd, { maxBuffer: 2000 * 1024 });
        return output;
      } catch (error) {
        return error;
      }
    };

    const response = await getNpmAudit();
    const advisories = JSON.parse(response.stdout).advisories;
    const actions = JSON.parse(response.stdout).actions;

    fs.writeFileSync(path.join(outputPath, "test.json"), response.stdout);

    let vulnerabilities = [];

    let npmCommands = null;

    if (advisories && Object.keys(advisories).length > 0) {
      Object.keys(advisories).forEach((advisory) => {
        const getNpmCommands = () => {
          const resolveArr = [];
          Object.keys(actions).forEach((action) => {
            const actionObj = actions[action];
            const packages = [];
            const ids = [];
            actionObj.resolves.forEach((r) => {
              packages.push(r.path.split(">")[0]);
              ids.push(r.id);
            });

            const resolveObj = {
              cmd: `npm ${actionObj.action} ${actionObj.module}${
                actionObj.target ? `@` + actionObj.target : ""
              } ${actionObj.depth ? "--depth " + actionObj.depth : ""}`,
              packages: packages,
              ids: ids,
            };

            resolveArr.push(resolveObj);
          });

          return resolveArr;
        };

        npmCommands = getNpmCommands();

        const vulnerability = {
          id: advisory,
          name: advisories[advisory].module_name,
          severity: advisories[advisory].severity,
          info: advisories[advisory].url,
          dependencies: [],
        };

        advisories[advisory].findings.forEach((f) => {
          f.paths.forEach((p) => {
            const package = p.split(">")[0];
            if (vulnerability.dependencies.includes(package)) return;

            vulnerability.dependencies.push(package);
          });
        });
        vulnerabilities.push(vulnerability);
      });
    }

    if (devDependencies) {
      Object.entries(devDependencies).forEach(([dependency, version]) => {
        vulnerabilities.forEach((v) => {
          if (v.dependencies.includes(dependency)) {
            const comment =
              npmCommands !== null
                ? npmCommands
                    .filter((c) => c.ids.includes(parseInt(v.id, 10)))
                    .map((c) => c.cmd)
                    .reduce((prev, current, currentIndex, array) => {
                      return (
                        prev +
                        current +
                        (arrayIsAtEnd(array, currentIndex) ? "" : " && ")
                      );
                    }, "")
                : undefined;

            data.push([
              name,
              dependency,
              version,
              true,
              v.name,
              v.severity,
              comment === undefined ? "N/A" : comment,
              v.info,
            ]);
          }
        });
      });
    }

    if (dependencies) {
      Object.entries(dependencies).forEach(([dependency, version]) => {
        vulnerabilities.forEach((v) => {
          if (v.dependencies.includes(dependency)) {
            const comment =
              npmCommands !== null
                ? npmCommands
                    .filter((c) => c.ids.includes(parseInt(v.id, 10)))
                    .map((c) => c.cmd)
                    .reduce((prev, current, currentIndex, array) => {
                      return (
                        prev +
                        current +
                        (arrayIsAtEnd(array, currentIndex) ? "" : " && ")
                      );
                    }, "")
                : undefined;

            data.push([
              name,
              dependency,
              version,
              false,
              v.name,
              v.severity,
              comment === undefined ? "N/A" : comment,
              v.info,
            ]);
          }
        });
      });
    }

    data.push([]);
  })
).then(() => {
  let csvContent = data.map((e) => e.join(";")).join("\n");

  fs.writeFileSync(path.join(outputPath, "package-overview.csv"), csvContent);
});
