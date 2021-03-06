FROM ubuntu:18.04
# the timezone is set (if it is not set, a user prompt will be launched)
ENV TZ=Europe/Madrid
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
# PHP 7.2 is installed and some aditional packages
RUN apt-get -y update && \
apt-get install -y php7.2 php7.2-bcmath php7.2-cli php7.2-common php7.2-curl php7.2-gd php7.2-gmp \
php7.2-intl php7.2-json php7.2-mbstring php7.2-mysql php7.2-opcache php7.2-pgsql php7.2-phpdbg \
php7.2-readline php7.2-sqlite3 php7.2-xml php7.2-xmlrpc php7.2-zip php-xdebug \
wget unzip vim
# Composer in installed
RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
RUN php composer-setup.php --install-dir=/usr/local/bin --filename=composer
# the files are added
COPY . /app
WORKDIR /app
# Finally init.sh is launched to install dependencies, configure .env and launch the server
CMD composer install && \
cp .env .env.local && \
sed -i -r 's,(DATABASE_URL=).*,\1'"$DATABASE_URL"',' ./.env.local && \
sed -i -r 's,(APP_ENV=).*,\1'"$ENV"',' ./.env.local && \
sed -i -r 's,(.*)(driver: ).*,\1\2'"$DRIVER"',' ./config/packages/doctrine.yaml && \
sed -i -r 's,(.*)( charset: ).*,\1\2'"$CHARSET"',' ./config/packages/doctrine.yaml && \
sed -i -r 's,(.*)(collate: ).*,\1\2'"$COLLATE"',' ./config/packages/doctrine.yaml && \
./bin/console server:run 0.0.0.0:80
