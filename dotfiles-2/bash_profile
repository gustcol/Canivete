export PS1='\u@\h \w $ '

alias _docker_run='docker run -ti --rm -v $HOME/.vimrc:/root/.vimrc'
alias _docker_run_aws='_docker_run -v $HOME/.aws:/root/.aws'
alias aws-shell='_docker_run_aws  pahud/aws-shell'
alias py-boto='_docker_run_aws -v $PWD:/root/dev:rw jpbarto/boto3'
alias boto-dev='_docker_run_aws -v $PWD:/root/dev:rw jpbarto/boto3 sh'
alias ghci='_docker_run jpbarto/ghci'
alias ghci-dev='_docker_run -v $PWD:/root/dev:rw jpbarto/ghci bash'
alias go-dev='_docker_run -v $HOME:/root -v $PWD:/root/dev:rw golang bash'
alias redis-cli='_docker_run redis redis-cli'
alias jekyll='_docker_run -v $PWD:/srv/jekyll -p 4000:4000 jekyll/builder jekyll'
alias github-pages='_docker_run -v $PWD:/usr/src/app -p 4000:4000 starefossen/github-pages'

# Add GHC 7.8.4 to the PATH, via https://ghcformacosx.github.io/
export GHC_DOT_APP="/Applications/GHC.app"
if [ -d "$GHC_DOT_APP" ]; then
  export PATH="${HOME}/.local/bin:${HOME}/.cabal/bin:${GHC_DOT_APP}/Contents/bin:${PATH}"
fi

export PATH=$PATH:/usr/local/aws/bin
complete -C `which aws_completer` aws
