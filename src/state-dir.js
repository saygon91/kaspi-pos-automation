import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Каталог для файлов, которые сервис создаёт сам и которые обязаны пережить
 * пересборку контейнера: личность устройства, ключевые пары, вебхуки,
 * отслеживаемые платежи.
 *
 * Почему это вынесено: deviceId/installId попадают в подписываемый конверт
 * каждого авторизованного вызова Kaspi, а подпись делается ключом из
 * keypair.json. Если при редеплое эти файлы пересоздаются, все ранее
 * установленные сессии перестают проходить проверку на стороне Kaspi —
 * то есть обычный деплой тихо убивает все подключённые кассы.
 *
 * По умолчанию — корень проекта, как было раньше: локальная разработка и
 * запуск без тома ничего не замечают.
 */
export const STATE_DIR = process.env.STATE_DIR || path.resolve(__dirname, '..');

fs.mkdirSync(STATE_DIR, { recursive: true });

/** Путь к файлу состояния по имени. */
export const statePath = (name) => path.join(STATE_DIR, name);
