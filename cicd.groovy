node('linux') 
{
        stage ('Poll') {
                checkout([
                        $class: 'GitSCM',
                        branches: [[name: '*/main']],
                        doGenerateSubmoduleConfigurations: false,
                        extensions: [],
                        userRemoteConfigs: [[url: 'https://github.com/ZOSOpenTools/opensslport.git']]])
        }

        stage('Build') {
                build job: 'Port-Pipeline', parameters: [string(name: 'REPO', value: 'opensslport'), string(name: 'DESCRIPTION', value: 'OpenSSL is a software library for applications that secure communications over computer networks against eavesdropping or need to identify the party at the other end.' )]
        }
}
