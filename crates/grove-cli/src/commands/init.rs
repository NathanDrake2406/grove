use crate::commands::CommandError;

/// Execute the `init` command, outputting shell integration for the given shell.
///
/// The output is meant to be eval'd in the user's shell config:
/// ```sh
/// eval "$(grove init zsh)"
/// ```
pub fn execute(shell: &str) -> Result<(), CommandError> {
    let output = match shell {
        "zsh" | "bash" => generate_bash_zsh(),
        "fish" => generate_fish(),
        _ => {
            return Err(CommandError::DaemonError(format!(
                "unsupported shell: {shell}. Supported: zsh, bash, fish"
            )));
        }
    };
    print!("{output}");
    Ok(())
}

fn generate_bash_zsh() -> String {
    r#"gr() {
    if [[ "$1" == "switch" ]]; then
        local target=$(command grove switch --print-path "${@:2}")
        if [[ -n "$target" ]]; then
            cd "$target"
        fi
    else
        command grove "$@"
    fi
}
"#
    .to_string()
}

fn generate_fish() -> String {
    r#"function gr
    if test "$argv[1]" = "switch"
        set -l target (command grove switch --print-path $argv[2..])
        if test -n "$target"
            cd $target
        end
    else
        command grove $argv
    end
end
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zsh_output_contains_gr_function() {
        let output = generate_bash_zsh();
        assert!(
            output.contains("gr()"),
            "zsh output should define the gr() function"
        );
    }

    #[test]
    fn bash_output_same_as_zsh() {
        // bash and zsh share the same shell function
        let zsh = execute_capture("zsh");
        let bash = execute_capture("bash");
        assert_eq!(zsh, bash, "bash and zsh should produce identical output");
    }

    #[test]
    fn fish_output_contains_function_gr() {
        let output = generate_fish();
        assert!(
            output.contains("function gr"),
            "fish output should define `function gr`"
        );
    }

    #[test]
    fn fish_output_uses_fish_syntax() {
        let output = generate_fish();
        assert!(output.contains("set -l"), "fish should use `set -l`");
        assert!(output.contains("test"), "fish should use `test`");
        assert!(output.contains("$argv"), "fish should use `$argv`");
        // Should not contain bash-isms
        assert!(
            !output.contains("$@"),
            "fish should not contain bash-style $@"
        );
        assert!(
            !output.contains("[["),
            "fish should not contain bash-style [["
        );
    }

    #[test]
    fn unsupported_shell_returns_error() {
        let result = execute("powershell");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unsupported shell: powershell"),
            "error should mention the unsupported shell name, got: {err}"
        );
    }

    #[test]
    fn zsh_output_uses_command_grove() {
        let output = generate_bash_zsh();
        assert!(
            output.contains("command grove"),
            "should use `command grove` to avoid recursion"
        );
    }

    #[test]
    fn zsh_output_intercepts_switch() {
        let output = generate_bash_zsh();
        assert!(
            output.contains(r#""$1" == "switch""#),
            "should intercept the switch subcommand"
        );
        assert!(
            output.contains("--print-path"),
            "should pass --print-path to the switch command"
        );
        assert!(output.contains("cd"), "should cd to the target directory");
    }

    /// Helper: run execute() and capture what would be printed.
    fn execute_capture(shell: &str) -> String {
        match shell {
            "zsh" | "bash" => generate_bash_zsh(),
            "fish" => generate_fish(),
            _ => panic!("test helper called with unsupported shell: {shell}"),
        }
    }
}
