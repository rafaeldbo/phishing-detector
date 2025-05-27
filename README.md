# *Phishing-Detector*
Esse projeto trata-se de uma API de detecção de possíveis URL's de páginas Phishing (páginas criadas com o intuito de enganar o usuário a fim de obter informações confidênciais). Esse projeto foi desenvolvido para a displina de Tecnologias Hacker do curso de Engenharia da Computação do Insper 2025.1 

## *Funcionalidades Implementadas*
- Detecção de números substituindo letras em um domínio
- Detecção de carácteres especiais 
- Uso de subdomínios excessivos
- Verificação de uso de DNS Dinâmico
- Detecção de redirecionamentos Suspeitos
- Consulta a lista de Phinshing Conhecidas ([Phishing-Database](https://github.com/Phishing-Database/Phishing.Database) e [Google Safe Browsing](https://developers.google.com/safe-browsing/?hl=pt_BR))
- Validação da Idade do domínio no registro WHOIS
- Validadação do Certificado SSL do domínio
- Semelhança do domínio com domínios de marcas usando Distâcnia de Levenshtein
- Presença ou semelhança com nome de marcas conhecidas

A aplicação também conta com uma interface interativa que facilita sua utilização disponível em [rafaeldbo/phishing-frontend](https://github.com/rafaeldbo/phishing-frontend)

## *Utilizando Localmente*
Certifique-se de possuir tanto o *Node* quanto o *Python* (de preferência o 3.10+) instalados e estar executando em um ambiente *Linux*. Execute os comendos em sequência:

- Clorando os repositórios
```
git clone https://github.com/rafaeldbo/phishing-detector.git
git clone https://github.com/rafaeldbo/phishing-frontend.git
```
- Caso queira, inicie um ambiente virtual python antes de continuar
```
python3 -m pip install -r ./phishing-detector/requirements.txt
```
- Após a intalação das dependências, renicie o terminal e inicie a API com:
```
fastapi run ./phishing-detector/app/main.py --port 8000
```
- Agora, paar instalar as dependências da interface e inicia-la execute:
```
cd phishing-frontend
npm i
npm run start
```

### *Chaves de API*
Para realizar a consulta ao [Google Safe Browsing](https://developers.google.com/safe-browsing/?hl=pt_BR) é necessário uma chave de API do google com o serviço `Google Safe Browsing` ativado. Para que a aplicação tenha acessa a essa chave crie um arquivo `.env` no local em que você está executando os comando (onde o repositório foi cloonado) com a variavel `GOOGLE_API_KEY`, como exeplificado no arquivo [.env.exemple](./.env.exemple)`.

## *Desenvolvedor*
- Rafael Dourado Bastos de Oliveira
