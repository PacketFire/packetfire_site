FROM library/nginx:1.13.3-alpine

COPY public /usr/share/nginx/html
EXPOSE 80
