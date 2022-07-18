node('linux') 
{
        stage('Build') {
                build job: 'Port-Pipeline', parameters: [string(name: 'REPO', value: 'opensslport'), string(name: 'DESCRIPTION', 'opensslport' )]
        }
}
