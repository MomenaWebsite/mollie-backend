"""
Percentage-Based Trading Bot voor Bitvavo
Verkoopt bij 5% winst of 5% verlies
"""
import logging
import time
import sys
import json
from datetime import datetime
from config import *
from bitvavo_client import BitvavoClient
from percentage_strategy import PercentageStrategy

# Configureer logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('trading_bot.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class TradingBot:
    def __init__(self):
        """Initialiseer de trading bot"""
        self.client = BitvavoClient()
        self.strategy = PercentageStrategy()
        self.trading_pairs = TRADING_PAIRS
        self.trade_amount = TRADE_AMOUNT_EUR
        self.running = False
        self.positions = {}  # Houd buy prices bij: {market: {'buy_price': float, 'amount': float}}
        self.last_sell_times = {}  # Houd laatste verkoop tijden bij: {market: timestamp}
        
        # Laad opgeslagen posities (voor als bot herstart)
        self.load_positions()
        self.load_last_sell_times()
        
        # Synchroniseer posities met Bitvavo (verwijder posities die niet meer bestaan)
        self.sync_positions_with_bitvavo()
        
        logger.info("=" * 60)
        logger.info("🤖 Percentage-Based Trading Bot gestart")
        logger.info(f"📈 Trading Pairs: {', '.join(self.trading_pairs)}")
        logger.info(f"💰 Trade amount per pair: {self.trade_amount} {QUOTE_CURRENCY}")
        logger.info(f"🛑 Stop Loss: {STOP_LOSS_PERCENTAGE}%")
        logger.info(f"🎯 Take Profit: {TAKE_PROFIT_PERCENTAGE}%")
        logger.info(f"📊 Max open posities: {MAX_OPEN_POSITIONS}")
        logger.info(f"📉 Koop bij daling: {BUY_ON_DIP_PERCENTAGE}% of meer")
        logger.info(f"⏳ Cooldown na verkoop: {COOLDOWN_AFTER_SELL_MINUTES} minuten")
        logger.info("=" * 60)
    
    def load_positions(self):
        """Laad opgeslagen posities uit bestand"""
        try:
            with open('positions.json', 'r') as f:
                self.positions = json.load(f)
                logger.info(f"✅ Geladen {len(self.positions)} posities uit positions.json")
        except FileNotFoundError:
            self.positions = {}
            logger.info("📝 Geen opgeslagen posities gevonden, start met lege posities")
        except Exception as e:
            logger.error(f"❌ Fout bij laden posities: {e}")
            self.positions = {}
    
    def save_positions(self):
        """Sla posities op in bestand"""
        try:
            with open('positions.json', 'w') as f:
                json.dump(self.positions, f, indent=2)
        except Exception as e:
            logger.error(f"❌ Fout bij opslaan posities: {e}")
    
    def load_last_sell_times(self):
        """Laad laatste verkoop tijden uit bestand"""
        try:
            with open('last_sell_times.json', 'r') as f:
                data = json.load(f)
                self.last_sell_times = {k: float(v) for k, v in data.items()}
        except FileNotFoundError:
            self.last_sell_times = {}
        except Exception as e:
            logger.error(f"❌ Fout bij laden last sell times: {e}")
            self.last_sell_times = {}
    
    def save_last_sell_times(self):
        """Sla laatste verkoop tijden op in bestand"""
        try:
            with open('last_sell_times.json', 'w') as f:
                json.dump(self.last_sell_times, f, indent=2)
        except Exception as e:
            logger.error(f"❌ Fout bij opslaan last sell times: {e}")
    
    def sync_positions_with_bitvavo(self):
        """Synchroniseer positions.json met werkelijke posities in Bitvavo"""
        try:
            logger.info("🔄 Start synchronisatie met Bitvavo posities...")
            
            # Haal werkelijke posities op van Bitvavo
            actual_positions = self.get_current_positions()
            
            logger.info(f"📊 Bitvavo heeft {len(actual_positions)} actieve posities:")
            for market, data in actual_positions.items():
                logger.info(f"   - {market}: {data['amount']:.8f} (waarde: ~{data['value']:.2f} EUR)")
            
            logger.info(f"📝 positions.json heeft {len(self.positions)} posities:")
            for market in self.positions.keys():
                logger.info(f"   - {market}")
            
            # Verwijder posities uit positions.json die niet meer bestaan in Bitvavo
            positions_to_remove = []
            for market in list(self.positions.keys()):
                if market not in actual_positions:
                    positions_to_remove.append(market)
                    logger.warning(f"🗑️ Verwijder positie {market} uit positions.json (niet meer in Bitvavo)")
            
            for market in positions_to_remove:
                del self.positions[market]
            
            # Voeg nieuwe posities toe die wel in Bitvavo zijn maar niet in positions.json
            positions_added = []
            for market, position_data in actual_positions.items():
                if market not in self.positions:
                    positions_added.append(market)
                    logger.warning(f"➕ Voeg nieuwe positie toe: {market} (koop prijs: huidige prijs {position_data['current_price']:.2f})")
                    self.positions[market] = {
                        'buy_price': position_data['current_price'],
                        'amount': position_data['amount']
                    }
            
            # ALTIJD opslaan na synchronisatie (ook als er geen wijzigingen zijn)
            self.save_positions()
            
            if positions_to_remove or positions_added:
                logger.info(f"✅ Posities gesynchroniseerd: {len(positions_to_remove)} verwijderd, {len(positions_added)} toegevoegd")
            else:
                logger.info(f"✅ Posities zijn al gesynchroniseerd: {len(self.positions)} actieve posities")
            
            logger.info(f"📊 Huidige posities na synchronisatie: {list(self.positions.keys())}")
            
        except Exception as e:
            logger.error(f"❌ Fout bij synchroniseren posities: {e}", exc_info=True)
    
    def check_balance(self):
        """Controleer beschikbare balance"""
        balance = self.client.get_balance(QUOTE_CURRENCY)
        if balance:
            logger.info(f"💵 Balance {QUOTE_CURRENCY}: {balance['available']:.2f} beschikbaar")
            return balance['available']
        return 0
    
    def get_current_positions(self):
        """Haal huidige posities op van Bitvavo"""
        current_positions = {}
        for market in self.trading_pairs:
            base_currency = market.split('-')[0]
            balance = self.client.get_balance(base_currency)
            if balance and balance['available'] > 0.00000001:  # Minimaal bedrag
                current_price = self.client.get_ticker_price(market)
                if current_price:
                    current_positions[market] = {
                        'amount': balance['available'],
                        'current_price': current_price,
                        'value': balance['available'] * current_price
                    }
        return current_positions
    
    def execute_buy(self, market, buy_price=None):
        """Voer buy order uit en verifieer dat deze succesvol is"""
        base_currency = market.split('-')[0]
        balance = self.check_balance()
        
        if balance < self.trade_amount:
            logger.warning(f"⚠️ Onvoldoende balance: {balance:.2f} {QUOTE_CURRENCY}")
            return False
        
        current_price = self.client.get_ticker_price(market)
        if not current_price:
            logger.error(f"❌ Kan prijs niet ophalen voor {market}")
            return False
        
        buy_price = buy_price or current_price
        
        logger.info(f"🟢 Plaats buy order voor {market}: {self.trade_amount} {QUOTE_CURRENCY} @ {buy_price:.2f}")
        
        if BITVAVO_TESTMODE:
            logger.warning("🧪 TESTMODE - Geen echte orders worden geplaatst!")
            # Simuleer aankoop
            amount = self.trade_amount / buy_price
            self.positions[market] = {'buy_price': buy_price, 'amount': amount}
            self.save_positions()
            logger.info(f"[TEST] Zou {amount:.8f} {base_currency} kopen @ {buy_price:.2f}")
            return True
        
        # Haal huidige balance op VOOR de order
        balance_before = self.client.get_balance(base_currency)
        amount_before = balance_before['available'] if balance_before else 0.0
        
        # Plaats de order
        result = self.client.place_market_buy_order_quote(market, self.trade_amount)
        
        if not result:
            logger.error(f"❌ Order plaatsen mislukt voor {market}")
            return False
        
        # Check of er een error in de response zit
        if isinstance(result, dict) and 'error' in result:
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"❌ Order error: {error_msg}")
            return False
        
        # Wacht even zodat de order kan worden uitgevoerd (market orders zijn meestal direct)
        logger.info(f"⏳ Wacht op order uitvoering...")
        time.sleep(2)  # Wacht 2 seconden
        
        # Haal nieuwe balance op NA de order
        balance_after = self.client.get_balance(base_currency)
        if not balance_after:
            logger.error(f"❌ Kan balance niet ophalen na order voor {base_currency}")
            return False
        
        amount_after = balance_after['available']
        amount_bought = amount_after - amount_before
        
        # Verifieer dat er daadwerkelijk crypto is gekocht
        if amount_bought <= 0.00000001:  # Minimaal bedrag (afronding)
            logger.error(f"❌ Geen {base_currency} gekocht! Balance voor: {amount_before:.8f}, na: {amount_after:.8f}")
            logger.error(f"   Order response: {result}")
            return False
        
        # Bereken werkelijke buy price uit order response of gebruik huidige prijs
        if isinstance(result, dict) and 'fills' in result and len(result['fills']) > 0:
            # Gebruik gemiddelde prijs van fills
            total_cost = sum(float(fill.get('price', 0)) * float(fill.get('amount', 0)) for fill in result['fills'])
            total_amount = sum(float(fill.get('amount', 0)) for fill in result['fills'])
            if total_amount > 0:
                buy_price = total_cost / total_amount
                logger.info(f"💰 Werkelijke buy price uit order: {buy_price:.2f}")
        else:
            # Gebruik huidige prijs als fallback
            logger.info(f"💰 Gebruik geschatte buy price: {buy_price:.2f}")
        
        # Sla positie op met werkelijke hoeveelheid
        self.positions[market] = {
            'buy_price': buy_price,
            'amount': amount_bought
        }
        self.save_positions()
        
        logger.info(f"✅ Buy order succesvol uitgevoerd!")
        logger.info(f"   Gekocht: {amount_bought:.8f} {base_currency}")
        logger.info(f"   Buy price: {buy_price:.2f}")
        logger.info(f"   Totale waarde: ~{amount_bought * buy_price:.2f} {QUOTE_CURRENCY}")
        
        return True
    
    def execute_sell(self, market, amount, reason, pct_change):
        """Voer sell order uit en verifieer dat deze succesvol is"""
        base_currency = market.split('-')[0]
        quote_currency = market.split('-')[1]
        
        if amount <= 0:
            logger.warning(f"⚠️ Geen {base_currency} om te verkopen")
            return False
        
        current_price = self.client.get_ticker_price(market)
        if not current_price:
            logger.error(f"❌ Kan prijs niet ophalen voor {market}")
            return False
        
        estimated_value = amount * current_price
        
        logger.info(f"🔴 Plaats sell order voor {market}: {amount:.8f} {base_currency} @ {current_price:.2f}")
        logger.info(f"   Reden: {reason} ({pct_change:.2f}%)")
        logger.info(f"   Geschatte waarde: ~{estimated_value:.2f} {QUOTE_CURRENCY}")
        
        if BITVAVO_TESTMODE:
            logger.warning("🧪 TESTMODE - Geen echte orders worden geplaatst!")
            logger.info(f"[TEST] Zou {amount:.8f} {base_currency} verkopen")
            # Verwijder positie
            if market in self.positions:
                del self.positions[market]
                self.save_positions()
            # Sla verkoop tijd op
            self.last_sell_times[market] = time.time()
            self.save_last_sell_times()
            return True
        
        # Haal huidige balance op VOOR de order
        balance_before = self.client.get_balance(quote_currency)
        eur_before = balance_before['available'] if balance_before else 0.0
        
        # Plaats de order
        result = self.client.place_market_sell_order(market, amount)
        
        if not result:
            logger.error(f"❌ Sell order plaatsen mislukt voor {market}")
            return False
        
        # Check of er een error in de response zit
        if isinstance(result, dict) and 'error' in result:
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"❌ Order error: {error_msg}")
            return False
        
        # Wacht even zodat de order kan worden uitgevoerd (market orders zijn meestal direct)
        logger.info(f"⏳ Wacht op order uitvoering...")
        time.sleep(2)  # Wacht 2 seconden
        
        # Haal nieuwe balance op NA de order
        balance_after = self.client.get_balance(quote_currency)
        if not balance_after:
            logger.error(f"❌ Kan balance niet ophalen na order voor {quote_currency}")
            return False
        
        eur_after = balance_after['available']
        eur_received = eur_after - eur_before
        
        # Verifieer dat er daadwerkelijk EUR is ontvangen
        if eur_received <= 0.01:  # Minimaal bedrag (afronding)
            logger.error(f"❌ Geen {quote_currency} ontvangen! Balance voor: {eur_before:.2f}, na: {eur_after:.2f}")
            logger.error(f"   Order response: {result}")
            return False
        
        # Verwijder positie alleen als verkoop succesvol was
        if market in self.positions:
            del self.positions[market]
            self.save_positions()
        
        # Sla verkoop tijd op voor cooldown
        self.last_sell_times[market] = time.time()
        self.save_last_sell_times()
        
        logger.info(f"✅ Sell order succesvol uitgevoerd!")
        logger.info(f"   Verkocht: {amount:.8f} {base_currency}")
        logger.info(f"   Ontvangen: {eur_received:.2f} {quote_currency}")
        logger.info(f"   Verkoop prijs: ~{eur_received / amount:.2f}")
        
        return True
    
    def check_and_sell_positions(self):
        """Check alle posities op stop loss / take profit"""
        current_positions = self.get_current_positions()
        
        # Verwijder eerst posities uit positions.json die niet meer bestaan in Bitvavo
        positions_to_remove = []
        for market in list(self.positions.keys()):
            if market not in current_positions:
                positions_to_remove.append(market)
                logger.warning(f"🗑️ Verwijder oude positie {market} uit positions.json (niet meer in Bitvavo)")
        
        for market in positions_to_remove:
            del self.positions[market]
        
        if positions_to_remove:
            self.save_positions()
            logger.info(f"✅ {len(positions_to_remove)} oude posities verwijderd")
        
        # Check nu alle bestaande posities op stop loss / take profit
        for market, position_data in current_positions.items():
            if market not in self.positions:
                # Nieuwe positie die we niet hebben, voeg toe met huidige prijs
                logger.warning(f"⚠️ Onbekende positie gevonden voor {market}, voeg toe met huidige prijs")
                self.positions[market] = {
                    'buy_price': position_data['current_price'],
                    'amount': position_data['amount']
                }
                self.save_positions()
                continue
            
            buy_price = self.positions[market]['buy_price']
            current_price = position_data['current_price']
            amount = position_data['amount']
            
            # Check stop loss / take profit
            sell_reason = self.strategy.should_sell(buy_price, current_price)
            
            if sell_reason:
                reason_type, pct_change = sell_reason
                self.execute_sell(market, amount, reason_type, pct_change)
            else:
                # Toon huidige status
                pct_change = self.strategy.calculate_profit_loss_percentage(buy_price, current_price)
                logger.info(f"📊 {market}: {pct_change:+.2f}% (Koop: {buy_price:.2f}, Nu: {current_price:.2f})")
    
    def find_best_crypto_to_buy(self):
        """
        Vind de beste crypto om nu in te stappen
        Koopt alleen bij goede timing (prijsdaling) en na cooldown periode
        """
        # Tel aantal open posities
        open_positions_count = len(self.positions)
        
        if open_positions_count >= MAX_OPEN_POSITIONS:
            logger.info(f"⏸️ Max aantal posities bereikt ({MAX_OPEN_POSITIONS})")
            return None
        
        # Zoek crypto's waar we nog geen positie in hebben
        available_pairs = [pair for pair in self.trading_pairs if pair not in self.positions]
        
        if not available_pairs:
            logger.info("⏸️ Alle crypto's hebben al een positie")
            return None
        
        # Check cooldown en prijsdaling voor elke beschikbare crypto
        best_pair = None
        best_dip = 0
        
        current_time = time.time()
        cooldown_seconds = COOLDOWN_AFTER_SELL_MINUTES * 60
        
        for market in available_pairs:
            # Check cooldown na laatste verkoop
            if market in self.last_sell_times:
                last_sell_time = self.last_sell_times[market]
                time_since_sell = current_time - last_sell_time
                
                if time_since_sell < cooldown_seconds:
                    minutes_left = (cooldown_seconds - time_since_sell) / 60
                    logger.debug(f"⏳ {market}: Cooldown actief ({minutes_left:.1f} minuten resterend)")
                    continue
            
            # Check prijsdaling (koop alleen bij dip)
            try:
                candles = self.client.get_candles(market, CANDLE_INTERVAL, limit=24)
                if not candles or len(candles) < 2:
                    continue
                
                current_price = candles[-1]['close']
                previous_price = candles[-2]['close']  # Vorige candle
                
                # Bereken prijsdaling percentage
                price_change_pct = ((current_price - previous_price) / previous_price) * 100
                
                # Alleen kopen als prijs is gedaald (negatief percentage)
                if price_change_pct <= -BUY_ON_DIP_PERCENTAGE:
                    logger.info(f"📉 {market}: Prijsdaling van {price_change_pct:.2f}% gedetecteerd")
                    if price_change_pct < best_dip:  # Kies de grootste daling
                        best_dip = price_change_pct
                        best_pair = market
                else:
                    logger.debug(f"📊 {market}: Prijsverandering {price_change_pct:+.2f}% (niet genoeg daling, nodig: -{BUY_ON_DIP_PERCENTAGE}%)")
            
            except Exception as e:
                logger.warning(f"⚠️ Fout bij analyseren {market}: {e}")
                continue
        
        if best_pair:
            logger.info(f"✅ Beste koop moment: {best_pair} (daling: {best_dip:.2f}%)")
            return best_pair
        else:
            logger.info(f"⏸️ Geen goede koop momenten gevonden (wacht op prijsdaling van min. {BUY_ON_DIP_PERCENTAGE}%)")
            return None
    
    def run_iteration(self):
        """Voer één iteratie uit"""
        try:
            logger.info("=" * 60)
            logger.info(f"🔄 Nieuwe iteratie")
            
            # Check alle bestaande posities op stop loss/take profit
            self.check_and_sell_positions()
            
            # Check of we nieuwe posities kunnen openen
            best_crypto = self.find_best_crypto_to_buy()
            
            if best_crypto:
                balance = self.check_balance()
                if balance >= self.trade_amount:
                    current_price = self.client.get_ticker_price(best_crypto)
                    if current_price:
                        logger.info(f"💡 Nieuwe positie mogelijk voor {best_crypto}")
                        self.execute_buy(best_crypto, current_price)
                else:
                    logger.info(f"⏸️ Onvoldoende balance voor nieuwe positie")
            
            logger.info("=" * 60)
            
        except Exception as e:
            logger.error(f"❌ Fout in trading iteratie: {e}", exc_info=True)
    
    def run(self):
        """Start de trading bot loop"""
        self.running = True
        
        logger.info(f"🚀 Bot gestart - Check interval: {CHECK_INTERVAL_SECONDS} seconden")
        logger.info(f"⏰ Start tijd: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            while self.running:
                try:
                    self.run_iteration()
                except KeyboardInterrupt:
                    logger.info("🛑 Gestopt door gebruiker")
                    break
                except Exception as e:
                    logger.error(f"❌ Onverwachte fout: {e}", exc_info=True)
                
                logger.info(f"⏳ Wacht {CHECK_INTERVAL_SECONDS} seconden...")
                time.sleep(CHECK_INTERVAL_SECONDS)
        
        except KeyboardInterrupt:
            logger.info("🛑 Bot gestopt door gebruiker")
        finally:
            self.running = False
            self.save_positions()
            self.save_last_sell_times()
            logger.info("👋 Bot afgesloten")

def main():
    """Main entry point"""
    try:
        bot = TradingBot()
        bot.run()
    except Exception as e:
        logger.error(f"❌ Fout bij starten bot: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
