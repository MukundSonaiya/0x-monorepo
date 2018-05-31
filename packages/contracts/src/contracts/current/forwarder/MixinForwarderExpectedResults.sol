pragma solidity ^0.4.24;
pragma experimental ABIEncoderV2;

import "./MixinForwarderCore.sol";

contract MixinForwarderExpectedResults is MixinForwarderCore {

    /// @dev Simulates the 0x Exchange fillOrder validation and calculations, without performing any state changes.
    /// @param order An Order struct containing order specifications.
    /// @param takerAssetFillAmount A number representing the amount of this order to fill.
    /// @return fillResults Amounts filled and fees paid by maker and taker.
    function calculateFillOrderFillResults(Order memory order, uint256 takerAssetFillAmount)
        public
        view
        returns (Exchange.FillResults memory fillResults)
    {
        Exchange.OrderInfo memory orderInfo = EXCHANGE.getOrderInfo(order);
        uint8 _status;
        (_status, fillResults) = EXCHANGE.calculateFillResults(
            order,
            orderInfo.orderStatus,
            orderInfo.orderTakerAssetFilledAmount,
            takerAssetFillAmount
        );
        return fillResults;
    }

    /// @dev Calculates a FillResults total for selling takerAssetFillAmount over all orders. 
    ///      Including the fees required to be paid. 
    /// @param orders An array of Order struct containing order specifications.
    /// @param takerAssetFillAmount A number representing the amount of this order to fill.
    /// @return totalFillResults Amounts filled and fees paid by maker and taker.
    function calculateMarketSellFillResults(Order[] memory orders, uint256 takerAssetFillAmount)
        internal
        view
        returns (Exchange.FillResults memory totalFillResults)
    {
        for (uint256 i = 0; i < orders.length; i++) {
            require(areBytesEqual(orders[i].makerAssetData, orders[0].makerAssetData), SAME_ASSET_TYPE_REQUIRED);
            uint256 remainingTakerAssetFillAmount = safeSub(takerAssetFillAmount, totalFillResults.takerAssetFilledAmount);

            Exchange.FillResults memory fillOrderExpectedResults = calculateFillOrderFillResults(orders[i], remainingTakerAssetFillAmount);

            addFillResults(totalFillResults, fillOrderExpectedResults);
            if (totalFillResults.takerAssetFilledAmount == takerAssetFillAmount) {
                break;
            }
        }
        return totalFillResults;
    }

    /// @dev Calculates a total FillResults for buying makerAssetFillAmount over all orders.
    ///      Including the fees required to be paid. 
    /// @param orders An array of Order struct containing order specifications.
    /// @param makerAssetFillAmount A number representing the amount of this order to fill.
    /// @return totalFillResults Amounts filled and fees paid by maker and taker.
    function calculateMarketBuyFillResults(Order[] memory orders, uint256 makerAssetFillAmount)
        public
        view
        returns (Exchange.FillResults memory totalFillResults)
    {
        for (uint256 i = 0; i < orders.length; i++) {
            require(areBytesEqual(orders[i].makerAssetData, orders[0].makerAssetData), SAME_ASSET_TYPE_REQUIRED);
            uint256 remainingMakerAssetFillAmount = safeSub(makerAssetFillAmount, totalFillResults.makerAssetFilledAmount);
            uint256 remainingTakerAssetFillAmount = getPartialAmount(
                orders[i].takerAssetAmount,
                orders[i].makerAssetAmount,
                remainingMakerAssetFillAmount);

            Exchange.FillResults memory calculatedFillOrderResults = calculateFillOrderFillResults(orders[i], remainingTakerAssetFillAmount);

            addFillResults(totalFillResults, calculatedFillOrderResults);
            if (totalFillResults.makerAssetFilledAmount == makerAssetFillAmount) {
                break;
            }
        }
        return totalFillResults;
    }

    /// @dev Calculates fill results for buyFeeTokens. This handles fees on buying ZRX
    ///      so the end result is the expected amount of ZRX (not less after fees).
    /// @param orders An array of Order struct containing order specifications.
    /// @param zrxAmount A number representing the amount zrx to buy
    /// @return totalFillResults Expected fill result amounts from buying fees
    function calculateBuyFeesFillResults(
        Order[] memory orders,
        uint256 zrxAmount)
        public
        view
        returns (Exchange.FillResults memory totalFillResults)
    {
        address token = readAddress(orders[0].makerAssetData, 0);
        require(token == address(ZRX_TOKEN), TAKER_ASSET_ZRX_REQUIRED);
        for (uint256 i = 0; i < orders.length; i++) {
            require(areBytesEqual(orders[i].makerAssetData, orders[0].makerAssetData), SAME_ASSET_TYPE_REQUIRED);
            uint256 remainingMakerAssetFillAmount = safeSub(zrxAmount, totalFillResults.makerAssetFilledAmount);
            // Convert the remaining amount of makerToken to buy into remaining amount
            // of takerToken to sell, assuming entire amount can be sold in the current order
            uint256 remainingTakerAssetFillAmount = getPartialAmount(
                orders[i].takerAssetAmount,
                safeSub(orders[i].makerAssetAmount, orders[i].takerFee), // our exchange rate after fees 
                remainingMakerAssetFillAmount);
            Exchange.FillResults memory singleFillResult = calculateFillOrderFillResults(orders[i], safeAdd(remainingTakerAssetFillAmount, 1));

            singleFillResult.makerAssetFilledAmount = safeSub(singleFillResult.makerAssetFilledAmount, singleFillResult.takerFeePaid);
            addFillResults(totalFillResults, singleFillResult);
            // As we compensate for the rounding issue above have slightly more ZRX than the requested zrxAmount
            if (totalFillResults.makerAssetFilledAmount >= zrxAmount) {
                break;
            }
        }
        return totalFillResults;
    }
}