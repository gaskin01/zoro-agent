FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install
COPY . .
RUN npm run build
ENV PORT=7860
EXPOSE 7860
CMD ["node", "dist/index.js"]
