node('linux') 
{
        stage('Build') {
                build job: 'Port-Pipeline', parameters: [string(name: 'REPO', value: 'opensslport'), string(name: 'DESCRIPTION', 'OpenSSL is a software library for applications that secure communications over computer networks against eavesdropping or need to identify the party at the other end.' )]
        }
}
